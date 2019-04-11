package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.net.SocketTimeoutException;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();
    private static LinkedList QueuedQueries = new LinkedList<DNSQuery>();

    private static Random random = new Random();
    private static int queryPointer = 0;
    private static DNSNode currentNode;

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        currentNode = node;
        QueuedQueries.clear();
        printResults(node, getResults(node,0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        // First check if indirectionLevel <= 10
        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        // Check if information is in cache
        Set<ResourceRecord> resultsInCache = cache.getCachedResults(node);
        if (resultsInCache.size() > 0) {
            return resultsInCache;
        }

        // Try querying server
        DNSQuery query = QueuedQueries.size() > 0 ? (DNSQuery) QueuedQueries.pollLast() : new DNSQuery(node, rootServer);

        retrieveResultsFromServer(query.getNode(), query.getServer(), indirectionLevel);

        // Did the query update the cache with desired results?
        resultsInCache = cache.getCachedResults(node);
        String nextText = "";
        if (resultsInCache.size() > 0) nextText = resultsInCache.iterator().next().getTextResult();
        if (resultsInCache.size() > 0 && (nextText.equals("SOA") || nextText.equals("MX") || nextText.equals("rCode Error"))) {
            return Collections.emptySet();
        } else if (resultsInCache.size() > 0) {
            return resultsInCache;
        }


        // If not, call getResults again with indirectionLevel + 1
        return getResults(node, indirectionLevel);
    }

    private static String getName(byte[] result, int tempPointer) {
        int len = result[tempPointer++] & 0xFF; // get the length of the domain
        String domainName = "";
        while (len != 0) {
            // Need to check if compression is used --> when first two bits are set to 11 --> '1100 0000'
            if (len >= 192) {
                // Compression is used as indicated by "1100 0000 0000 0000"
                // Get the pointer to the FQDN

                int pointer = (result[tempPointer++] & 0xFF) + 256 * (len - 192);

                // Since a compression pointer could point to another compression, need to recursively call
                domainName += getName(result, pointer);
                break;

            } else {
                for (int i = 0; i < len; i++) {
                    domainName += (char) (result[tempPointer++] & 0xFF);
                }
                domainName += '.';
            }
            len = result[tempPointer++] & 0xFF;
        }

        return domainName;
    }

    /**
     * Decodes the DNS responses' Resource Records.
     */

    private static ResourceRecord decodeResourceRecord(byte[] result) {
        ResourceRecord record = null;

        int tempPointer = queryPointer;
        // Increment queryPointer according to if pointer is found
        if ((result[queryPointer] & 0xFF) >= 192) {
            queryPointer += 2;
        } else {
            while ((result[queryPointer] & 0xFF) != 0) {
                queryPointer++;
            }
            queryPointer++;
        }

        String domainName = getName(result, tempPointer);

        int RRType = (result[queryPointer++] & 0xFF << 8) + (result[queryPointer++] & 0xFF);
        int RRClass = (result[queryPointer++] & 0xFF << 8) + (result[queryPointer++] & 0xFF);
        int RRTimeToLive = ((result[queryPointer++] & 0xFF) << 24) + ((result[queryPointer++] & 0xFF) << 16) + ((result[queryPointer++] & 0xFF) << 8) + (result[queryPointer++] & 0xFF);
        int RRRDLength = (result[queryPointer++] & 0xFF << 8) + (result[queryPointer++] & 0xFF); // Specifies the length of the RDATA

        String RData = "";

        if (RRType == 1) { // IPV4
            for (int i = 0; i < RRRDLength; i++) {
                int name = (result[queryPointer++] & 0xFF);
                RData += name + ".";
            }
            RData = RData.substring(0, RData.length() - 1); // Remove the last '.'
            InetAddress addr = null;
            try {
                addr = InetAddress.getByName(RData);
                record = new ResourceRecord(domainName, RecordType.getByCode(RRType), RRTimeToLive, addr);
                verbosePrintResourceRecord(record, 0);
            } catch (UnknownHostException e){
                System.out.println(e);
            }

        } else if (RRType == 28) { // IPV6
            // IPV6 has 128-bits - 8 sets of 16 bits -> need to read two bytes at a time
            // Since we're reading in two bytes at a time, need only iterate through half the RRRDLength
            for (int i = 0; i < RRRDLength / 2; i++) {
                int name16Bits = (((result[queryPointer++] & 0xFF) << 8) + (result[queryPointer++] & 0xFF));
                String nameHex = Integer.toHexString(name16Bits);
                RData += nameHex + ":";
            }
            RData = RData.substring(0, RData.length() - 1); // Remove the last ':'
            InetAddress addr = null;
            try {
                addr = InetAddress.getByName(RData);
                record = new ResourceRecord(domainName, RecordType.getByCode(RRType), RRTimeToLive, addr);
                verbosePrintResourceRecord(record, 0);
            } catch (UnknownHostException e){
                System.out.println(e);
            }

        } else if (RRType == 2 || RRType == 5) {
            String name = getName(result, queryPointer);
            queryPointer += RRRDLength;
            record = new ResourceRecord(domainName, RecordType.getByCode(RRType), RRTimeToLive, name);
            verbosePrintResourceRecord(record, 0);

        } else if (RRType == 0) {
            String name = getName(result, queryPointer);
            queryPointer += RRRDLength;
            record = new ResourceRecord(domainName, RecordType.getByCode(RRType), RRTimeToLive, name);
        }
        else { // handle SOA and MX
            String name = getName(result, queryPointer);
            queryPointer += RRRDLength;
            record = new ResourceRecord(domainName, RecordType.getByCode(RRType), RRTimeToLive, name);
            verbosePrintResourceRecord(record, 0);
        }

        cache.addResult(record);

        return record;
    }

    /**
     * Decodes the DNS response.
     *
     * @param node Host name and record type used for the query.
     * @return encoded DNS query in byte array.
     */

    // parse the byte array from the results
    private static void decodeResponse(byte[] result, DNSNode node, int indirectionLevel) {
        int aa = (result[2] & 0x04) >>> 2; // Masked by 0000 0100, shifted by 2 to get 6th digit
        boolean authoritative = (aa == 1) ? true : false;
        if (verboseTracing) System.out.println("Response ID " + (((result[0] & 0xFF) << 8) + (result[1] & 0xFF)) + " Authoritative = " + authoritative);
        int len = result.length;
        int id = ((result[0] & 0xFF) << 8) + (result[1] & 0xFF); // Masked to get unsigned integer
        int qr = (result[2] & 0x80) >>> 7; // To get first digit
        int opCode = (result[2] & 0x78) >>> 3; // Masked by 0111 1000 and then shifted right by 3 to get 2,3,4,5 th digits

        int tc = (result[2] & 0x02) >>> 1;
        int rd = (result[2] & 0x01);
        int ra = (result[3] & 0x80) >>> 7; // get 1st bit of byte
        int rCode = (result[3] & 0x0F); // Skipped Z

        // TODO: need to handle the different cases of rCode
        // do we need to print the messages to tracing?

        int qdCount = ((result[4] & 0xFF) << 8) + (result[5] & 0xFF);
        int anCount = ((result[6] & 0xFF) << 8) + (result[7] & 0xFF);

        int nsCount = ((result[8] & 0xFF) << 8) + (result[9] & 0xFF);

        int arCount = ((result[10] & 0xFF) << 8) + (result[11] & 0xFF);

        int labelOctLen = (result[12] & 0xFF);
        queryPointer = 13;
        String qNameFromResponse = "";

        while (labelOctLen != 0) {
            for (int i = 0; i < labelOctLen; i++) {
                char c = (char) (result[queryPointer++] & 0xFF);
                qNameFromResponse += c;
            }
            qNameFromResponse += '.';
            labelOctLen = (result[queryPointer++] & 0xFF);
        }

        int qType = ((result[queryPointer++] & 0xFF) << 8) + (result[queryPointer++] & 0xFF);
        int qClass = ((result[queryPointer++] & 0xFF) << 8) + (result[queryPointer++] & 0xFF);

        // Address the Resource Records: ANCOUNT, NSCOUNT, ARCOUNT
        if (verboseTracing) System.out.println("  Answers (" + anCount + ")");
        ResourceRecord record = null;

        ArrayList<ResourceRecord> answerRecords = new ArrayList<>();
        for (int i = 0; i < anCount; i++) {
            record = decodeResourceRecord(result);
            if (record != null) answerRecords.add(record);
        }

        if (verboseTracing) System.out.println("  Nameservers (" + nsCount + ")");
        ArrayList<ResourceRecord> nameServerRecords = new ArrayList<>();
        for (int i = 0; i < nsCount; i++) {
            record = decodeResourceRecord(result);
            if (record != null) nameServerRecords.add(record);
        }

        if (verboseTracing) System.out.println("  Additional Information (" + arCount + ")");
        ArrayList<ResourceRecord> additionalRecords = new ArrayList<>();
        for (int i = 0; i < arCount; i++) {
            record = decodeResourceRecord(result);
            if (record != null) additionalRecords.add(record);
        }

        ArrayList<ResourceRecord> resolvedNameServers = new ArrayList<>();
        if (aa == 0) {

            // Check to see if we have the IP address in the additonal information
            for (ResourceRecord ns : nameServerRecords) {
                String textName = ns.getTextResult();
                for (ResourceRecord addRR : additionalRecords) {
                    // If no addRR is of type 1 or 28, then we know we don't have the needed info
                    if ((addRR.getHostName().equals(textName) && addRR.getType().getCode() == 1))
                    {
                        resolvedNameServers.add(addRR);
                    }
                }
            }

            // If you cannot find the IP for this ns, we must resolve it using getResults
            if (resolvedNameServers.isEmpty()) {
                // for (int i = nameServerRecords.size() - 1; i > 0; i--) {
                    String nameServerName = nameServerRecords.get(0).getTextResult();

                    // Need to query with new lookup
                    DNSNode NSNode = new DNSNode(nameServerName, RecordType.getByCode(1));
                    // The next query would be to query the nameServerName with root server
                    QueuedQueries.offerLast(new DNSQuery(NSNode, rootServer));
                    // resolve this name server
                    Set<ResourceRecord> resultsInCache = getResults(NSNode, 0);

                    resolvedNameServers.add(resultsInCache.iterator().next());
                    QueuedQueries.clear();
                // }
            }

            // for (int j = resolvedNameServers.size() - 1; j > 0; j--) {
                // Next query would be to query IP address from additional information with the original DNSnode
                QueuedQueries.add(new DNSQuery(node, resolvedNameServers.get(0).getInetResult()));
            // }
        } else {
            if (rCode == 3 || rCode == 5 || rCode == 1 || rCode == 2 || rCode == 4) {
                cache.addResult(new ResourceRecord(node.getHostName(), node.getType(), 3600, "rCode Error"));
            }
            for (ResourceRecord ns : nameServerRecords) {
                if (ns.getNode().getType().getCode() == 6) {
                    cache.addResult(new ResourceRecord(node.getHostName(), node.getType(), ns.getTTL(), "SOA"));
                } else if (ns.getNode().getType().getCode() == 15) {
                    cache.addResult(new ResourceRecord(node.getHostName(), node.getType(), ns.getTTL(), "MX"));
                }
            }

            if (!answerRecords.isEmpty()) {
                for (ResourceRecord as : answerRecords) {
                    if (as.getNode().getType().getCode() == 5) {
                        // If the answer is type is CNAME
                        QueuedQueries.clear();

                        DNSNode CNAMENode = new DNSNode(as.getTextResult(), node.getType());
                        QueuedQueries.offerLast(new DNSQuery(CNAMENode, rootServer));
                        Set<ResourceRecord> CNAMEResults = getResults(CNAMENode, indirectionLevel + 1);
                        ResourceRecord CNAMEResult = CNAMEResults.iterator().next();
                        cache.addResult(new ResourceRecord(node.getHostName(), CNAMEResult.getNode().getType(), CNAMEResult.getTTL(), CNAMEResult.getInetResult()));
                    } else {
                        // If the answer type is A
                        cache.addResult(new ResourceRecord(node.getHostName(), node.getType(), as.getTTL(), as.getInetResult()));
                    }
                }
            }
        }
        return;
    }

    /**
     * Formats the header of a DNS query.
     *
     * @param node Host name and record type used for the query.
     * @return encoded DNS query in byte array.
     */

    private static byte[] formatMessage(DNSNode node, byte[] queryID) {
        // 1 byte is 8 bits
        byte[] query = new byte[512];
        // format header
        query[0] = queryID[0];
        query[1] = queryID[1];

        int qr = 0; // 1 bit; 0 = query; 1 = response
        int opCode = 0; // 4 bits; 0 = standard query; 1 = inverse query; 2 = server status request
        int aa = 0; // something about authoritative answer? prob not really relevant
        int tc = 0; // truncation - if the msg was truncated
        int rd = 0; // iterative or recurive - need to do iterative for this assignment
        int queryParams = qr + opCode + aa + tc + rd;
        query[2] = (byte) queryParams; // this byte would contain QR, OPCODE, AA, TC, and RD

        int ra = 0; // recursive available;
        int z = 0; // reserved for future use
        int rCode = 0; // response code: 0 - no error, 1 - format error, 2 - server failure, 3 - name error, 4 - not implemented, 5 - refused
        int queryParams1 = ra + z + rCode;
        query[3] = (byte) queryParams1; // this byte would contain RA, Z, and RCODE

        int qdCount = 1; // unsigned 16 bit int; #of queries
        query[4] = (byte) 0;
        query[5] = (byte) qdCount;

        int anCount = 0; // unsigned 16 bit int; #of responses
        query[6] = (byte) 0;
        query[7] = (byte) anCount;

        int nsCount = 0; // unsigned 16 bit int; #of name server RRs
        query[8] = (byte) 0;
        query[9] = (byte) nsCount;

        int arCount = 0; // unsigned 16 bit int; #of additional RRs
        query[10] = (byte) 0;
        query[11] = (byte) arCount;

        // To know where question section starts
        int whereHeaderEnded = 12;

        // format question
        String hostName = node.getHostName();
        String[] hostLabels = hostName.split("\\."); // to get the different domain levels
        for (String s : hostLabels) {
            query[whereHeaderEnded++] = (byte) s.length(); // get length of e.g. 'www'
            char[] sChar = s.toCharArray();
            for (char c : sChar) {
                query[whereHeaderEnded++] = (byte) ((int) c); // turn characters into ascii
            }
        }
        query[whereHeaderEnded++] = (byte) 0; // To end the QNAME

        int qType = node.getType().getCode();
        query[whereHeaderEnded++] = (byte) 0;
        query[whereHeaderEnded++] = (byte) qType;

        int qClass = 1; // 1 for internet - it's always internet
        query[whereHeaderEnded++] = (byte) 0;
        query[whereHeaderEnded++] = (byte) qClass;

        return Arrays.copyOfRange(query, 0, whereHeaderEnded);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server, int indirectionLevel) {
        // initialize header with two random bytes used for query id
        byte[] id = generateRandomId();

        if (verboseTracing) System.out.println("Query ID     " + (((id[0] & 0xFF) << 8) + (id[1] & 0xFF)) + " " + node.getHostName() + "  " + node.getType() + " --> " + server.getHostAddress());

        byte[] encodedQuery = formatMessage(node, id);
        DatagramPacket packet = new DatagramPacket(encodedQuery, encodedQuery.length, server, DEFAULT_DNS_PORT);

        try {
            // send message
            socket.send(packet);
        } catch (Exception e) {
            // break;
        }

        byte[] emptyByteArray = new byte[1024];
        DatagramPacket receivedPacket = new DatagramPacket(emptyByteArray, emptyByteArray.length);
        try {
            socket.receive(receivedPacket);
            String received = new String(receivedPacket.getData(), 0, receivedPacket.getLength());

            // receive authoritative name servers from decoding the response
            decodeResponse(emptyByteArray, node, indirectionLevel);
            // store results in cache?
            return;
        } catch (Exception e) {
            System.out.println(e);
            // break;
        }
    return;
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing) {
            String hostName = record.getHostName();
            hostName = hostName.substring(0, hostName.length()-1);
            System.out.format("       %-30s %-10d %-4s %s\n", hostName,
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
        }
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }

    private static byte[] generateRandomId() {
        byte[] id = new byte[2];
        random.nextBytes(id);
        random.nextBytes(id);
        return id;
    }
}
