package br.ufpe.gprt.floodlight.transparentCache;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.gtp.AbstractGTP;

public class GTPTunnelContext {

	private AbstractGTP gtp;
	private UDP udp;
	private IPv4 ip;
	private Ethernet eth;

	public GTPTunnelContext updateContext(Ethernet eth) {
		this.eth = eth;
		if (eth.getEtherType().equals(EthType.IPv4)) {
			this.ip = (IPv4) eth.getPayload();
			
			if (ip.getProtocol().equals(IpProtocol.UDP)) {
				this.udp = (UDP) ip.getPayload();
				

				if (udp.getSourcePort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getSourcePort().equals(UDP.GTP_CONTROL_PORT)
						|| udp.getDestinationPort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getDestinationPort()
								.equals(UDP.GTP_CONTROL_PORT)) {
					this.gtp = (AbstractGTP) udp.getPayload();
					
					return this;
				}
			} else if (ip.getProtocol().equals(IpProtocol.TCP)) {
				return this;
			}
		}
		
		throw new RuntimeException("Malformed GTP Tunnel context. Only GTPv1 on top of UDP supported for now.");
	}
	
	public GTPTunnelContext getNextSeqNumberContext(){
		
		byte[] seqNumber = null;
		if(this.gtp != null){
			seqNumber = this.gtp.getHeader().getSequenceNumber();
			this.gtp.getHeader().setSequenceNumber(this.gtp.getHeader().getNextSequenceNumber());
		}
		this.ip.setIdentification((short)(this.ip.getIdentification()+1));
		
		Ethernet cloneContext = (Ethernet) eth.clone();
		GTPTunnelContext clone = new GTPTunnelContext();
		clone.updateContext(cloneContext);
		
		if(seqNumber != null){
			this.gtp.getHeader().setSequenceNumber(seqNumber);
		}
		
		return clone;
	}

	public Ethernet getPacketWithPayload(IPv4 ackGTPIp) {
		GTPTunnelContext nextSeqNum = this.getNextSeqNumberContext();
		nextSeqNum.setPayload(ackGTPIp);
		return nextSeqNum.eth;
	}

	private void setPayload(IPv4 ackGTPIp) {
		if(this.gtp == null){
			this.eth.setPayload(ackGTPIp);
			ackGTPIp.setParent(this.eth);
			this.ip = ackGTPIp;
		} else {
			this.gtp.setPayload(ackGTPIp);
			ackGTPIp.setParent(this.gtp);
		}
		
		this.eth.resetChecksum();
		this.ip.resetChecksum();
		
		if(this.udp != null){
			this.udp.resetChecksum();
		}
		
		ackGTPIp.resetChecksum();
	}

}
