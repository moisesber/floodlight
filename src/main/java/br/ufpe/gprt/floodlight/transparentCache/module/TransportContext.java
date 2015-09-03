package br.ufpe.gprt.floodlight.transparentCache.module;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.gtp.AbstractGTP;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;

public class TransportContext {
	
	byte[] zeroShort = new byte[] { 0, 0};
	

	public TransportContext(){
	}
	
	public Ethernet reverseContext(Ethernet eth, TCP payload){
		
		Ethernet cloneEth = (Ethernet) eth.clone();
		
		cloneEth.setDestinationMACAddress(eth.getSourceMACAddress());
		cloneEth.setSourceMACAddress(eth.getDestinationMACAddress());
		
		if (eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();
			IPv4 cloneIP = (IPv4)ip.clone();
			
			if(cloneIP.getProtocol().equals(IpProtocol.UDP)){
				
//				test if it is GTP traffic
//				
//				reverse the context of the GTP traffic
				
				return null;

			} else {
				cloneIP.setIdentification((short)0);
				cloneIP.setSourceAddress(ip.getDestinationAddress());
				cloneIP.setDestinationAddress(ip.getSourceAddress());
				cloneIP.setPayload(payload);
				payload.setParent(cloneIP);
				
				cloneEth.setPayload(cloneIP);
				cloneIP.setParent(cloneEth);
				
				payload.resetChecksum();
				return cloneEth;
			}
		} else {
			return null;
		}
	}

	public Ethernet reverseContextGTP(Ethernet eth,
			TCP payload) {

		
		if (eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();
			
			if(ip.getProtocol().equals(IpProtocol.UDP)){
				UDP udp = (UDP) ip.getPayload();
				
				if (udp.getSourcePort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getDestinationPort().equals(UDP.GTP_CLIENT_PORT)) {
					AbstractGTP gtp = (AbstractGTP) udp.getPayload();
					
					IPv4 gtpIp = (IPv4) gtp.getPayload();

					
					Ethernet cloneEth = (Ethernet) eth.clone();
					IPv4 cloneIP = (IPv4)ip.clone();
					UDP cloneUDP = (UDP) udp.clone();
					AbstractGTP cloneGtp = (AbstractGTP) gtp.clone();
					IPv4 cloneGTPIp = (IPv4) gtpIp.clone();

					cloneEth.setDestinationMACAddress(eth.getSourceMACAddress());
					cloneEth.setSourceMACAddress(eth.getDestinationMACAddress());

					cloneIP.setIdentification((short)0);
					cloneIP.setSourceAddress(ip.getDestinationAddress());
					cloneIP.setDestinationAddress(ip.getSourceAddress());
					
					cloneUDP.setDestinationPort(udp.getSourcePort());
					cloneUDP.setSourcePort(udp.getDestinationPort());
					
					cloneGtp.getHeader().setSequenceNumber(zeroShort);
					
					cloneGTPIp.setIdentification((short)0);
					cloneGTPIp.setSourceAddress(gtpIp.getDestinationAddress());
					cloneGTPIp.setDestinationAddress(gtpIp.getSourceAddress());
					
					//rebuilding stack
					cloneEth.setPayload(cloneIP);
					cloneIP.setParent(cloneEth);
					cloneIP.setPayload(cloneUDP);
					cloneUDP.setParent(cloneIP);
					cloneUDP.setPayload(cloneGtp);
					cloneGtp.setParent(cloneUDP);
					
					cloneGTPIp.setPayload(payload);
					payload.setParent(cloneGTPIp);
					
					cloneGtp.setPayload(cloneGTPIp);
					cloneGTPIp.setParent(cloneGtp);

					
					payload.resetChecksum();
					
					return cloneEth;
				}
				
				return null;

			} 
		} 
		
		return null;
	}

}
