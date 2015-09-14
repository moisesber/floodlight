package br.ufpe.gprt.floodlight.transparentCache.module;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.gtp.AbstractGTP;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;

public class SplicingInfo {
	
	private IOFSwitch clientSw;
	private IPv4Address cacheAddress;
	private int cachePort;
	private TCP tcpGETMessage;
	private SplicingState state;
	private IPv4Address clientAddress;
	private int clientPort;
	private int originPort;
	private IPv4Address originAddress;
	private int initialOriginSequenceNumber;
	private int initialSEQFromSYNACK;
	private MacAddress clientMacAddress;
	private MacAddress originMacAddress;
	private int toClientTSValue;
	private int toClientTSecr;
	private IOFSwitch cacheSw;
	private GTPContext gtpContext;
	private Ethernet clientToCacheContext;
	private long synTimeStamp;

	public SplicingInfo(IPv4Address clientAddress, int clientPort, IPv4Address originAddress, int originPort, 
			IOFSwitch clientSw, IPv4Address cacheAddress, int cachePort, TCP tcp, MacAddress clientMacAddress, MacAddress originMacAddress) {
				this.clientAddress = clientAddress;
				this.clientPort = clientPort;
				this.originAddress = originAddress;
				this.originPort = originPort;
				this.clientSw = clientSw;
				this.cacheAddress = cacheAddress;
				this.cachePort = cachePort;
				this.tcpGETMessage = tcp;
				this.clientMacAddress = clientMacAddress;
				this.originMacAddress = originMacAddress;
				this.state = SplicingState.Created;
				this.initialOriginSequenceNumber = 0;
				this.gtpContext = null;
				this.synTimeStamp = -1;
	}

	public IOFSwitch getClientSw() {
		return clientSw;
	}
	
	public TCP getTcpGETMessage() {
		return tcpGETMessage;
	}

//	@Override
//	public int hashCode() {
//		final int prime = 19079;
//		int result = tdecpSourceIPId.hashCode();
//		result = prime * result + localPort;
//		result = prime * result + cacheAddress.hashCode();
//		result = prime * result + cachePort;
//		result = prime * result + sw.hashCode();
//		return result;
//	}

	public Ethernet getEthToCache(String localCacheMacAddress, TCP payload, MacAddress clientMacAddress) {
		
		Ethernet l2 = new Ethernet();
		l2.setDestinationMACAddress(MacAddress.of(localCacheMacAddress));
		l2.setSourceMACAddress(clientMacAddress);
		l2.setEtherType(EthType.IPv4);
		
		IPv4 l3 = new IPv4();
		l3.setSourceAddress(this.getClientAddress());
		l3.setDestinationAddress(this.cacheAddress);
		l3.setTtl((byte) 64);
		l3.setProtocol(IpProtocol.TCP);
		
		l2.setPayload(l3);
		l3.setParent(l2);
		
		l3.setPayload(payload);
		payload.setParent(l3);
		
		payload.resetChecksum();
		return l2;
	}

	public SplicingState getState() {
		return state;
	}

	public void setState(SplicingState state) {
		this.state = state;
	}

	public IPv4Address getCacheAddress() {
		return cacheAddress;
	}

	public int getCachePort() {
		return cachePort;
	}

	public IPv4Address getClientAddress() {
		return clientAddress;
	}

	public int getClientPort() {
		return clientPort;
	}

	public int getOriginPort() {
		return originPort;
	}

	public IPv4Address getOriginAddress() {
		return originAddress;
	}
	
	public boolean equalsToClientAddress(IPv4Address ip, int port){
		return this.equals(ip, port, clientAddress, clientPort);
	}
	
	public boolean equalsToOriginAddress(IPv4Address ip, int port){
		return this.equals(ip, port, originAddress, originPort);
	}
	
	public boolean equalsToCacheAddress(IPv4Address ip, int port){
		return this.equals(ip, port, cacheAddress, cachePort);
	}
	
	private boolean equals(IPv4Address ip, int port, IPv4Address otherIP, int otherPort){
		return ip.equals(otherIP) && port == otherPort;
	}

	public int getInitialOriginSequenceNumber() {
		return initialOriginSequenceNumber;
	}

	public void setInitialOriginSequenceNumber(int initialOriginSequenceNumber) {
		this.initialOriginSequenceNumber = initialOriginSequenceNumber;
	}

	public int getInitialSEQFromSYNACK() {
		return initialSEQFromSYNACK;
	}

	public void setInitialSEQFromSYNACK(int initialSEQFromSYNACK) {
		this.initialSEQFromSYNACK = initialSEQFromSYNACK;
	}

	public MacAddress getClientMacAddress() {
		return clientMacAddress;
	}

	public MacAddress getOriginMacAddress() {
		return originMacAddress;
	}

	public void setToClientTsValues(int[] tsValues) {
		this.toClientTSValue = tsValues[0];
		this.toClientTSecr = tsValues[1];
	}

	public int getToClientTSValue() {
		return toClientTSValue;
	}

	public int getToClientTSecr() {
		return toClientTSecr;
	}

	public void setCacheSw(IOFSwitch sw) {
		this.cacheSw = sw;
	}

	public IOFSwitch getCacheSw() {
		return cacheSw;
	}

	public void registerGTPContext(Ethernet eth) {
		
		if (eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();
			
			if(ip.getProtocol().equals(IpProtocol.UDP)){
				UDP udp = (UDP) ip.getPayload();
				
				if (udp.getSourcePort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getDestinationPort().equals(UDP.GTP_CLIENT_PORT)) {
					AbstractGTP gtp = (AbstractGTP) udp.getPayload();
					
					IPv4 gtpIp = (IPv4) gtp.getPayload();
					
					this.gtpContext = new GTPContext(eth, ip, udp, gtp, gtpIp);
				}
			}
		}
		
	}
	
	public boolean isGTPTunneled(){
		return this.gtpContext != null;
	}
	
	public GTPContext getGtpContext() {
		return gtpContext;
	}

	class GTPContext {
		
		public GTPContext(Ethernet eth2, IPv4 ip2, UDP udp2, AbstractGTP gtp2,
				IPv4 gtpIp2) {
					eth = eth2;
					ip = ip2;
					udp = udp2;
					gtp = gtp2;
					gtpIP = gtpIp2;
		}
		Ethernet eth;
		IPv4 ip;
		UDP udp;
		AbstractGTP gtp;
		IPv4 gtpIP;
		
		
		
		
		
		private byte[] shortToByteArray(short s){
			byte[] bytes = new byte[2];
			bytes[0] = (byte)(s & 0xff);
			bytes[1] = (byte)((s >> 8) & 0xff);
			
			return bytes;
		}





		public Ethernet getTunneledData(IPv4 ip, TCP tcp) {
			Data payloadData = (Data)tcp.getPayload();
			Ethernet cloneEth = (Ethernet) this.eth.clone();
			IPv4 cloneIP = (IPv4)this.ip.clone();
			UDP cloneUDP = (UDP)this.udp.clone();
			AbstractGTP cloneGTP = (AbstractGTP)this.gtp.clone();
//			IPv4 cloneGTPIP = (IPv4)gtpIP.clone();
			
			cloneIP.setIdentification(ip.getIdentification());
//			cloneIP.setIdentification((short)0);
			cloneGTP.getHeader().setSequenceNumber(shortToByteArray(cloneIP.getIdentification()));
//			cloneGTP.getHeader().setSequenceNumber(new byte[] { 0, 0 });
			
			
			//rebuilding stack
			cloneEth.setPayload(cloneIP);
			cloneIP.setParent(cloneEth);
			cloneIP.setPayload(cloneUDP);
			
			cloneUDP.setParent(cloneIP);
			cloneUDP.setPayload(cloneGTP);
			cloneGTP.setParent(cloneUDP);
			
			ip.setPayload(tcp);
			tcp.setParent(ip);
			
			
			cloneGTP.setPayload(ip);
			ip.setParent(cloneGTP);
			
			
			tcp.resetChecksum();
			return  cloneEth;
		}
		
	}
	
	
	public Ethernet getClientToCacheContext() {
		return clientToCacheContext;
	}

	public void registerClientToCacheContext(Ethernet eth) {
		eth.setPayload(null);
		this.clientToCacheContext = eth;
	}

	public void setSynTimeStamp(long synTimeStamp) {
		this.synTimeStamp = synTimeStamp;
	}

	public long getSynTimeStamp() {
		return synTimeStamp;
	}

}
