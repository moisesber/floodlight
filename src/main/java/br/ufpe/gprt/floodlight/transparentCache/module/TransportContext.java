package br.ufpe.gprt.floodlight.transparentCache.module;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

import org.projectfloodlight.openflow.types.EthType;

public class TransportContext {
	
	private Ethernet eth;

	public TransportContext(Ethernet eth){
		this.eth = eth;
	}
	
	public Ethernet reverseContext(short identification, TCP payload){
		
		if(identification == 0){
			//Setting a random value for identification
			//                            A prime
//			identification = (short) (new Random(7499)).nextInt(Short.MAX_VALUE + 1);
		}
		
		Ethernet cloneEth = (Ethernet) this.eth.clone();
		
		cloneEth.setDestinationMACAddress(this.eth.getSourceMACAddress());
		cloneEth.setSourceMACAddress(this.eth.getDestinationMACAddress());
		
		if (eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();
			IPv4 cloneIP = (IPv4)ip.clone();


			cloneIP.setIdentification(identification);
			cloneIP.setSourceAddress(ip.getDestinationAddress());
			cloneIP.setDestinationAddress(ip.getSourceAddress());
			cloneIP.setPayload(payload);
			payload.setParent(cloneIP);
			
			cloneEth.setPayload(cloneIP);
			cloneIP.setParent(cloneEth);
			
			payload.resetChecksum();
			return cloneEth;
		} else {
			return null;
		}
	}

}
