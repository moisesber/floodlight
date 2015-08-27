package br.ufpe.gprt.floodlight.transparentCache.module;

import org.projectfloodlight.openflow.types.IPv4Address;


public class  TCPIPConnection {


	private IPv4Address ip;
	private int port;

	public TCPIPConnection(IPv4Address ip, int port) {
		this.ip = ip;
		this.port = port;
	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof TCPIPConnection) {
			TCPIPConnection other = (TCPIPConnection) o;

			return this.ip.equals(other.ip)
					&& this.port == other.port;
		}

		return false;
	}

	@Override
	public int hashCode() {
		final int prime = 6911;
		int result = ip.hashCode();
		result = prime * result + port;
		return result;
	}

	public String toString() {
		return "address=" + this.ip + ":" + this.port;
	}

	public IPv4Address getIp() {
		return ip;
	}

	public int getPort() {
		return port;
	}

}
