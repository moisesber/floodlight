package br.ufpe.gprt.floodlight.tcpsplicing;

import java.lang.reflect.Method;

import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.gtp.AbstractGTP;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;

import com.google.common.primitives.UnsignedInteger;

public class ClientTCPSplicingInfo {
	
	private Ethernet context;
	private AbstractGTP gtp;
	private TCP tcp;
	private IPv4 gtpIp;
	private long contextTimeStamp;

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
		this.contextTimeStamp = System.currentTimeMillis();
		this.context = ((Ethernet)eth.clone());
		this.context.setDestinationMACAddress(eth.getSourceMACAddress());
		this.context.setSourceMACAddress(eth.getDestinationMACAddress());
//		this.context.setSourceMACAddress(MacAddress.of("ff:df:55:ff:ff:ff"));

//				.setDestinationMACAddress(MacAddress.of("ff:df:55:ff:ff:ff"))
//				.setDestinationMACAddress(MacAddress.BROADCAST)
//				.setSourceMACAddress(eth.getDestinationMACAddress());
		this.context.resetChecksum();
		
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
				

				if (udp.getSourcePort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getSourcePort().equals(UDP.GTP_CONTROL_PORT)
						|| udp.getDestinationPort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getDestinationPort()
								.equals(UDP.GTP_CONTROL_PORT)) {
					
					AbstractGTP gtp = (AbstractGTP) udp.getPayload();
					AbstractGTP cloneGtp = ((AbstractGTP)gtp.clone());
					udpClone.setPayload(cloneGtp);
					cloneGtp.setParent(udpClone);
					udpClone.resetChecksum();
					this.gtp = cloneGtp;

					if (!gtp.isControlPacket()) {
						IPv4 gtpIp = (IPv4) gtp.getPayload();
						this.gtpIp = ((IPv4) gtpIp.clone())
								.setDestinationAddress(gtpIp.getSourceAddress())
								.setSourceAddress(gtpIp.getDestinationAddress());
						this.gtp.setPayload(this.gtpIp);
						this.gtpIp.setParent(this.gtp);
						this.gtpIp.resetChecksum();

						if (gtpIp.getProtocol().equals(IpProtocol.TCP)) {
							TCP tcp = (TCP) gtpIp.getPayload();
							this.tcp = ((TCP) tcp.clone())
									.setDestinationPort(tcp.getSourcePort())
									.setSourcePort(tcp.getDestinationPort())
									.setAcknowledge(tcp.getSequence())
									.setSequence(tcp.getAcknowledge());
							this.gtpIp.setPayload(this.tcp);
							this.tcp.setParent(this.gtp);
						}
					}
				}
			}
		}
		
	}



	public void updateTCPContext(TCP updatedTCP) {
		this.tcp.setAcknowledge(updatedTCP.getSequence()).setSequence(
				updatedTCP.getAcknowledge());
	}



	public Ethernet getContext(byte[] bytes) {
		this.tcp.setPayload(new Data(bytes));
		return this.context;
	}
	
	public Ethernet getACK(){
		TCP clonedTCP = (TCP)this.tcp.clone();
		IPacket clonedPayload = (IPacket)this.tcp.getPayload().clone();
		
		
		this.tcp.setFlags((short)0x010);
		byte[] bytes = clonedPayload.serialize();
		System.out.println("Payload size is "+bytes.length);
		System.out.println("Seq is "+this.tcp.getSequence());
//		this.tcp.setAcknowledge(Integer.this.tcp.get + bytes.length);
		UnsignedInteger uAck = UnsignedInteger.asUnsigned(this.tcp.getAcknowledge());
		System.out.println("Ack is "+this.tcp.getAcknowledge());
		System.out.println("uAck is "+uAck);
		this.tcp.setAcknowledge(uAck.add(UnsignedInteger.asUnsigned(bytes.length)).intValue());
//		this.tcp.setWindowSize()
		this.gtp.getHeader().setSequenceNumber(this.gtp.getHeader().getNextSequenceNumber());

		this.tcp.setPayload(null);
		
		System.out.println("!!!!TCP flags = "+ Integer.toBinaryString(this.tcp.getFlags()));

		
		Ethernet cloneEth = (Ethernet)this.context.clone();
//		cloneEth.setPayload(this.tcp);
		this.tcp = clonedTCP;
		this.gtpIp.setPayload(clonedTCP);
		this.tcp.setPayload(clonedPayload);
		
		return cloneEth;
	}

}
