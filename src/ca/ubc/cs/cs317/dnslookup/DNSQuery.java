package ca.ubc.cs.cs317.dnslookup;
import java.net.InetAddress;

public class DNSQuery {
    private InetAddress server;
    private DNSNode node;

    public DNSQuery(DNSNode node, InetAddress server) {
        this.node = node;
        this.server = server;
    }
    public InetAddress getServer() {
        return server;
    }

    public DNSNode getNode() {
        return node;
    }
}
