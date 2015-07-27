package br.ufpe.gprt.floodlight.tcpsplicing;

import java.lang.reflect.Method;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.gtp.AbstractGTP;

public class ClientTCPSplicingInfo {
	
	private Ethernet context;

//    public static Map<String, List<SwapingInfo>> decodeMap;
//    static {
//    	SwapingInfo 
//    	
//    	ClientTCPSplicingInfo.decodeMap.put(IPv4.class.getName(), );
//    	
//    	
//	ClientTCPSplicingInfo.decodeMap.put((byte)2, UDP.class);
//	ClientTCPSplicingInfo.decodeMap.put((byte)2, TCP.class);
//	ClientTCPSplicingInfo.decodeMap.put((byte)2, AbstractGTP.class);
//    }

	class SwapingInfo {
		
		Method source;
		Method destination;
		
	}



	public void setContext(Ethernet eth) {
		this.context = ((Ethernet)eth.clone())
				.setDestinationMACAddress(eth.getSourceMACAddress())
				.setSourceMACAddress(eth.getDestinationMACAddress());
		
		if (eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();
			IPv4 ipClone = ((IPv4) ip.clone())
				.setDestinationAddress(ip.getSourceAddress())
				.setSourceAddress(ip.getDestinationAddress());
			this.context.setPayload(ipClone);
			ipClone.setParent(this.context);
			ipClone.resetChecksum();
			
			
			if (ip.getProtocol().equals(IpProtocol.UDP)) {
				UDP udp = (UDP) ip.getPayload();
				UDP udpClone = ((UDP) udp.clone())
						.setSourcePort(udp.getDestinationPort())
						.setDestinationPort(udp.getSourcePort());
				ipClone.setPayload(udpClone);
				udpClone.setParent(ipClone);
				udpClone.resetChecksum();
				

				if (udp.getSourcePort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getSourcePort().equals(UDP.GTP_CONTROL_PORT)
						|| udp.getDestinationPort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getDestinationPort()
								.equals(UDP.GTP_CONTROL_PORT)) {
					
					AbstractGTP gtp = (AbstractGTP) udp.getPayload();
//					logger.warn("GTP RECEIVED!");
//					
//					if (!gtp.isControlPacket()) {
//
//						IPv4 gtpIp = (IPv4) gtp.getPayload();
//						logger.warn("GTP NOT Control Packet Proto = "+gtpIp.getProtocol());
//
//						if (gtpIp.getProtocol().equals(IpProtocol.TCP)) {
//
//							TCP tcp = (TCP) gtpIp.getPayload();
//							logger.warn("TCP on top of GTP detected! port = "+tcp.getDestinationPort());
//
//							if (tcp.getDestinationPort().equals(
//									TransportPort.of(80))) {
//								
//							}
//						}
//					}
				}
			}
		}
	}
	

}
