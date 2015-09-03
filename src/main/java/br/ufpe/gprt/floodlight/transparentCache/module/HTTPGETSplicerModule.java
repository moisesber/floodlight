package br.ufpe.gprt.floodlight.transparentCache.module;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.gtp.AbstractGTP;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HTTPGETSplicerModule implements IFloodlightModule, IOFMessageListener {
	
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	private List<Inet4Address> localCaches;
	private TCPContextAnalyzer tcpContextAnalyzer;
	private TransportContext transportContextManager;
	private Map<TCPIPConnection, SplicingInfo> splicingClients;
	private int checksumRecalculations;


	protected static Logger logger;

	@Override
	public String getName() {
		return this.getClass().getName();
	}

	@Override
	// TODO Auto-generated method stub
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		if (eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();

			if (ip.getProtocol().equals(IpProtocol.TCP)) {
				TCP tcp = (TCP) ip.getPayload();
				
				return handleTraffic(sw, eth, ip, tcp);				
			} else if(ip.getProtocol().equals(IpProtocol.UDP)){
				UDP udp = (UDP) ip.getPayload();
				
				if (udp.getSourcePort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getDestinationPort().equals(UDP.GTP_CLIENT_PORT)) {
					AbstractGTP gtp = (AbstractGTP) udp.getPayload();
					
					IPv4 gtpIP = (IPv4) gtp.getPayload();
					
					if (gtpIP.getProtocol().equals(IpProtocol.TCP)) {
						TCP gtpTCP = (TCP)gtpIP.getPayload();
						
						return handleTraffic(sw, eth, gtpIP, gtpTCP);				
					}
				}
			}
		}

		return Command.CONTINUE;
	}

	private Command handleTraffic(IOFSwitch sw, Ethernet eth, IPv4 ip, TCP tcp) {
		//Registering all TCP traffic for now.
		//In the future, we should restrict to only TCP traffic to 
		//port 80 and to destinationAddress == oneOfTheknownHTTPServers

		int sourcePort = tcp.getSourcePort().getPort();
		IPv4Address sourceAddress = ip.getSourceAddress();
		int destinationPort = tcp.getDestinationPort().getPort();
		IPv4Address destinationAddress = ip.getDestinationAddress();
		
		TCPIPConnection sourceTCPIPId = new TCPIPConnection(sourceAddress, sourcePort);
		TCPIPConnection dstTCPIPId = new TCPIPConnection(destinationAddress, destinationPort);

		if(isFromLocalCache(sourceAddress)){
			//Content from local cache
			logger.debug("Receiving something from cache "+sourceAddress+" destination is "+dstTCPIPId);
			
			if(this.splicingClients.containsKey(dstTCPIPId)){
				SplicingInfo info = this.splicingClients.get(dstTCPIPId);
				
				logger.debug("From cache and destination is a splicing client "+dstTCPIPId+" splicing state = "+info.getState());
				
				if(info.getState().equals(SplicingState.Connected)){
					sendDataToClient(eth, ip, tcp, dstTCPIPId, info);
					
					
					if(this.tcpContextAnalyzer.checkIfFYNACKReceived(tcp)){
						//Local cache trying to end the connection
						info.setState(SplicingState.Sync);
					}
					
					return Command.STOP;
				} else if(info.getState().equals(SplicingState.Sync)){
					

					if(this.tcpContextAnalyzer.checkIfSYNACKReceived(tcp)){
						//New connection being made with the cache for a new client
						
						if(!info.getState().equals(SplicingState.Sync)){
							logger.debug("Receiving a SYNACK for a client already connected or not in Sync, something when wrong... "+info.getClientAddress()+ " "+info.getClientPort());
							return Command.STOP;
						}
						
						logger.debug("Receiving SYNACK from cache and destination is a splicing client, sending ACK");

						TCP ackToBeSent = this.tcpContextAnalyzer.getACKFromSYNACK(tcp);
						
//						sendDataToClient(eth, ip, ackToBeSent, dstTCPIPId, info);

						Ethernet ethtoSendACK = this.transportContextManager.reverseContext(eth, ackToBeSent);
						createAndSendPacketOut(sw, ethtoSendACK.serialize(),
								OFPort.FLOOD);
						
						info.setInitialSEQFromSYNACK(tcp.getSequence());
						info.setCacheSw(sw);
						
						TCP get = info.getTcpGETMessage();
						info.setInitialOriginSequenceNumber(get.getAcknowledge());

						get.setDestinationPort(info.getCachePort());
						get.setAcknowledge(ackToBeSent.getAcknowledge());
						get.setSequence(ackToBeSent.getSequence());
						get.setOptions(ackToBeSent.getOptions());
						get.resetChecksum();
						
						Ethernet ethtoSendGET = this.transportContextManager.reverseContext(eth, get);
						createAndSendPacketOut(sw, ethtoSendGET.serialize(),
								OFPort.FLOOD);
						
						return Command.STOP;
					}
					
					
					if(this.tcpContextAnalyzer.checkIfACKReceived(tcp)){
						
						info.setState(SplicingState.Connected);
						return Command.STOP;
					}
					
					if(this.tcpContextAnalyzer.checkIfFYNACKReceived(tcp)){
						sendDataToClient(eth, ip, tcp, dstTCPIPId, info);

						info.setState(SplicingState.Disconnecting);
						return Command.STOP;
					}
				} else if(info.getState().equals(SplicingState.Disconnecting)){
					//This means that the cache server sent a FYN ACK packet to the client
					if(this.tcpContextAnalyzer.checkIfACKReceived(tcp)){
						sendDataToClient(eth, ip, tcp, dstTCPIPId, info);

						info.setState(SplicingState.Disconnected);
						
						logger.info("Cache server sending ACK to the FYN ACK answer from the client, connection closed and info removed. recalc= "+checksumRecalculations);

						//Removed the splicing client from list of clients
						this.splicingClients.remove(sourceTCPIPId);
						return Command.STOP;
					}
				}
			}
		}
		
		if(this.splicingClients.containsKey(sourceTCPIPId)){
			//Source is one of the splicing clients
			SplicingInfo info = this.splicingClients.get(sourceTCPIPId);
			
			redirectDataFromClientToCache(eth, ip, tcp, info);

			if(info.getState().equals(SplicingState.Connected)){
				if(this.tcpContextAnalyzer.checkIfFYNACKReceived(tcp)){
					//Client is trying to end the session
					info.setState(SplicingState.Sync);
				}

			} else if(info.getState().equals(SplicingState.Disconnecting)){
				//Redirect the ACK
//						redirectDataFromClientToCache(eth, ip, tcp, info);
				
					//This means that the cache server sent a FYN ACK packet to the client
				if(this.tcpContextAnalyzer.checkIfACKReceived(tcp)){
					// and the client is "acking" it now.
					
					//Removed the splicing client from list of clients
					
					logger.info("Client sending ACK to the FYN ACK answer from the cache server, connection closed and info removed. recalc= "+checksumRecalculations);
					this.splicingClients.remove(sourceTCPIPId);
					info.setState(SplicingState.Disconnected);
				}
			} else if(info.getState().equals(SplicingState.Sync)){
//						redirectDataFromClientToCache(eth, ip, tcp, info);
				
				if(this.tcpContextAnalyzer.checkIfFYNACKReceived(tcp)){
					info.setState(SplicingState.Disconnecting);
				}


			}
			
			return Command.STOP;
		}
		
		if(this.splicingClients.containsKey(dstTCPIPId) && !isFromLocalCache(sourceAddress) ){
			return Command.STOP;
		}

		Data tcpData = (Data)tcp.getPayload();
		byte[] bytes = tcpData.getData();
		boolean isGetMethodForKnownHttpServer = this.checkGETToForeignHTTPServer(localCaches, ip, bytes);
		
		if(isGetMethodForKnownHttpServer){
			return sendACKAndRedirectGet(eth, ip, bytes, tcp, sw, sourceAddress, sourcePort, destinationAddress, destinationPort);
		}
		
		return Command.CONTINUE;
	}

	private void redirectDataFromClientToCache(Ethernet eth, IPv4 ip, TCP tcp,
			SplicingInfo info) {
		
		
		
		if(info.isGTPTunneled()){
			Ethernet contextFromClientToCache = info.getClientToCacheContext();

			contextFromClientToCache.setSourceMACAddress(info.getClientMacAddress());
			contextFromClientToCache.setDestinationMACAddress(this.getLocalCacheMacAddress(info.getCacheAddress()));

			ip.setDestinationAddress(info.getCacheAddress());
			tcp.setDestinationPort(info.getCachePort());
			
			int ack = (tcp.getAcknowledge() - info.getInitialOriginSequenceNumber()) + info.getInitialSEQFromSYNACK() + 1; 
			tcp.setAcknowledge(ack);

			contextFromClientToCache.setPayload(ip);
			ip.setParent(contextFromClientToCache);
			ip.setPayload(tcp);
			tcp.setParent(ip);
			
			tcp.resetChecksum();

			
			createAndSendPacketOut(info.getCacheSw(), contextFromClientToCache.serialize(),
					OFPort.FLOOD);
		} else {

			ip.setDestinationAddress(info.getCacheAddress());
			tcp.setDestinationPort(info.getCachePort());
			eth.setSourceMACAddress(info.getClientMacAddress());
			eth.setDestinationMACAddress(this.getLocalCacheMacAddress(info.getCacheAddress()));
			
			int ack = (tcp.getAcknowledge() - info.getInitialOriginSequenceNumber()) + info.getInitialSEQFromSYNACK() + 1; 
			tcp.setAcknowledge(ack);

			tcp.resetChecksum();

			createAndSendPacketOut(info.getCacheSw(), eth.serialize(),
					OFPort.FLOOD);
		}
	}

	private void sendDataToClient(Ethernet eth, IPv4 ip, TCP tcp,
			TCPIPConnection dstTCPIPId, SplicingInfo info) {
//		Ethernet cloneEth = (Ethernet)eth.clone();
//		IPv4 cloneIP = (IPv4)ip.clone();
//		TCP cloneTCP = (TCP)tcp.clone();
		
		Ethernet cloneEth = eth;
		
		if(!info.isGTPTunneled()){
			cloneEth.setDestinationMACAddress(info.getClientMacAddress());
			cloneEth.setSourceMACAddress(info.getOriginMacAddress());
			
			
			IPv4 cloneIP = ip;
			TCP cloneTCP = tcp;

			cloneIP.setSourceAddress(info.getOriginAddress());
			cloneTCP.setSourcePort(info.getOriginPort());
			int seq = (tcp.getSequence() - info.getInitialSEQFromSYNACK()) + info.getInitialOriginSequenceNumber() - 1; 
			cloneTCP.setSequence(seq);

			byte[] options = this.tcpContextAnalyzer.getOptionsWithNewTsValues(info.getToClientTSValue(), info.getToClientTSecr(), tcp.getOptions());
			cloneTCP.setOptions(options);


			
			cloneIP.setPayload(cloneTCP);
			cloneTCP.setParent(cloneIP);
			cloneEth.setPayload(cloneIP);
			cloneIP.setParent(cloneEth);

			
			short before = cloneTCP.getChecksum();
			cloneTCP.resetChecksum();
			
//			short[] checksums = this.getChecksum(cloneTCP);
//			short jsWrenchChecksum = checksums[2];
	//
	//
//			if (cloneTCP.getChecksum() != jsWrenchChecksum) {
//				logger.warn("Floodlight's code resulted in a different checksum than expected. "
//						+ "Expected was "+ Integer.toHexString(jsWrenchChecksum & 0xffff)
//						+ " flooligth result "+ Integer.toHexString(cloneTCP.getChecksum() & 0xffff)  
////						+ " array "+getStringFromByteArray(data, Integer.toHexString(jsWrenchChecksum & 0xffff))
////						+ " array "+getHexArrayFromByteArray(data, Integer.toHexString(jsWrenchChecksum & 0xffff))
//						+ " recalc = "+checksumRecalculations
//						);
//			}
	//
//			cloneTCP.setChecksum(jsWrenchChecksum);
//			
//			checksumRecalculations++;
			
			logger.debug("Reseting the checksum to splicing client "
					+ dstTCPIPId
					+ " splicing state = "
					+ info.getState()
					+ " Ocks="
					+ Integer.toHexString(tcp.getChecksum() & 0xffff)
					+ " before="
					+ Integer.toHexString(before & 0xffff)
					+ " after="
					+ Integer.toHexString(cloneTCP.getChecksum() & 0xffff)
//					+ " otherCode="
//					+ Integer
//							.toHexString(checksums[2] & 0xffff)
							);
		} else {
			
			
			IPv4 cloneIP = ip;
			TCP cloneTCP = tcp;

			cloneIP.setSourceAddress(info.getOriginAddress());
			cloneTCP.setSourcePort(info.getOriginPort());
			int seq = (tcp.getSequence() - info.getInitialSEQFromSYNACK()) + info.getInitialOriginSequenceNumber() - 1; 
			cloneTCP.setSequence(seq);

			byte[] options = this.tcpContextAnalyzer.getOptionsWithNewTsValues(info.getToClientTSValue(), info.getToClientTSecr(), tcp.getOptions());
			cloneTCP.setOptions(options);
			
			
			
			
			
			Ethernet[] packets = info.getGtpContext().getTunneledData(cloneIP, cloneTCP);
			
			for (Ethernet ethernet : packets) {
				logger.debug("Sending fragmented data to sw "+info.getClientSw());
				createAndSendPacketOut(info.getClientSw(), ethernet.serialize(),
						OFPort.FLOOD);
			}
			
			return ;
			
		}
		

		
		

		
		
		logger.debug("Sending data to sw "+info.getClientSw());
		createAndSendPacketOut(info.getClientSw(), cloneEth.serialize(),
				OFPort.FLOOD);
	}
	
	private String getStringFromByteArray(byte [] data, String checksum){
		return "String "+checksum+" = \""+(new String(data)+ "\"");
	}
	
	private String getHexArrayFromByteArray(byte[] data, String checksum){
		StringBuffer buffer = new StringBuffer();
		
		buffer.append("byte[] "+checksum+" = new byte[] {");
		
		for (byte b : data) {
//			buffer.append(b+",");
			buffer.append(" (byte)0x"+Integer.toHexString(b & 0xff)+",");
		}
		
		buffer.append("};");
		
		return buffer.toString();
	}
	
	public short[] getChecksum(TCP tcp){
        int length;
        byte dataOffset = tcp.getDataOffset();
        IPacket payload = tcp.getPayload();
        IPacket parent = tcp.getParent();
        short floodlightChecksum = 0;
        
        if (dataOffset == 0)
            dataOffset = 5;  // default header length
        length = dataOffset << 2;
        byte[] payloadData = null;
        if (payload != null) {
            payloadData = payload.serialize();
            length += payloadData.length;
        }

        byte[] data = new byte[length];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putShort((short)tcp.getSourcePort().getPort()); //TCP ports are defined to be 16 bits
        bb.putShort((short)tcp.getDestinationPort().getPort());
        bb.putInt(tcp.getSequence());
        bb.putInt(tcp.getAcknowledge());
        bb.putShort((short) (tcp.getFlags() | (dataOffset << 12)));
        bb.putShort(tcp.getWindowSize());
        bb.putShort(tcp.getChecksum());
        bb.putShort(tcp.getUrgentPointer((short)0));
        if (dataOffset > 5) {
            int padding;
            bb.put(tcp.getOptions());
            padding = (dataOffset << 2) - 20 - tcp.getOptions().length;
            for (int i = 0; i < padding; i++)
                bb.put((byte) 0);
        }
        if (payloadData != null)
            bb.put(payloadData);

        if (parent != null && parent instanceof IPv4)
            ((IPv4)parent).setProtocol(IpProtocol.TCP);

        IPv4 ipv4 = (IPv4) parent;
        // compute checksum if needed
        if (floodlightChecksum == 0) {
            bb.rewind();
            int accumulation = 0;
            
            // compute pseudo header mac
            if (parent != null && parent instanceof IPv4) {
            	
                accumulation += ((ipv4.getSourceAddress().getInt() >> 16) & 0xffff)
                        + (ipv4.getSourceAddress().getInt() & 0xffff);
                accumulation += ((ipv4.getDestinationAddress().getInt() >> 16) & 0xffff)
                        + (ipv4.getDestinationAddress().getInt() & 0xffff);
                accumulation += ipv4.getProtocol().getIpProtocolNumber() & 0xff;
                accumulation += length & 0xffff;
            }

            for (int i = 0; i < length / 2; ++i) {
                accumulation += 0xffff & bb.getShort();
            }
            // pad to an even number of shorts
            if (length % 2 > 0) {
                accumulation += (bb.get() & 0xff) << 8;
            }

            accumulation = ((accumulation >> 16) & 0xffff)
                    + (accumulation & 0xffff);
            floodlightChecksum = (short) (~accumulation & 0xffff);
            bb.putShort(16, floodlightChecksum);
        }
        
        short normalChecksum = checksum(data, 0, length);
        short tcpSpecificChecksum = checksum(ipv4.getSourceAddress().getBytes(), ipv4.getDestinationAddress().getBytes(),  
        		(byte)ipv4.getProtocol().getIpProtocolNumber(), (short)length, data, 0);
        
        return new short[] {floodlightChecksum, normalChecksum, tcpSpecificChecksum};
	}
	
	/**
	 * Specific checksum calculation used for the UDP and TCP pseudo-header.
	 */

	public static short checksum(byte[] source, byte[] destination,
			byte protocol, short length, byte[] message, int offset) {

		int bufferlength = length + 12;

		boolean odd = length % 2 == 1;

		if (odd) {
			++bufferlength;
		}

		byte[] buffer = new byte[bufferlength];

		buffer[0] = source[0];
		buffer[1] = source[1];
		buffer[2] = source[2];
		buffer[3] = source[3];

		buffer[4] = destination[0];
		buffer[5] = destination[1];
		buffer[6] = destination[2];
		buffer[7] = destination[3];

		buffer[8] = (byte) 0;
		buffer[9] = protocol;

		shortToBytes(length, buffer, 10);

		int i = 11;

		while (++i < length + 12) {
			buffer[i] = message[i + offset - 12];
		}

		if (odd) {
			buffer[i] = (byte) 0;
		}

		return checksum(buffer, buffer.length, 0);
	}

    //Checksum calculation based on the JSocket Wrench code
	// https://github.com/ehrmann/jswrench
	//The original code can be found at 
	//https://github.com/ehrmann/jswrench/blob/master/src/com/act365/net/SocketUtils.java
	private static long integralFromBytes(byte[] buffer, int offset, int length) {

		long answer = 0;

		while (--length >= 0) {
			answer = answer << 8;
			answer |= buffer[offset] >= 0 ? buffer[offset]
					: 0xffffff00 ^ buffer[offset];
			++offset;
		}

		return answer;
	}
    
    //Checksum calculation based on the JSocket Wrench code
	// https://github.com/ehrmann/jswrench
	//The original code can be found at 
	//https://github.com/ehrmann/jswrench/blob/master/src/com/act365/net/SocketUtils.java
	private static void shortToBytes(short value, byte[] buffer, int offset) {
		buffer[offset + 1] = (byte) (value & 0xff);
		value = (short) (value >> 8);
		buffer[offset] = (byte) (value);
	}
    
    //Checksum calculation based on the JSocket Wrench code
	// https://github.com/ehrmann/jswrench
	//The original code can be found at 
	//https://github.com/ehrmann/jswrench/blob/master/src/com/act365/net/SocketUtils.java
	public static short checksum(byte[] message, int length, int offset) {
		// Sum consecutive 16-bit words.

		int sum = 0;

		while (offset < length - 1) {

			sum += (int) integralFromBytes(message, offset, 2);

			offset += 2;
		}

		if (offset == length - 1) {

			sum += (message[offset] >= 0 ? message[offset]
					: message[offset] ^ 0xffffff00) << 8;
		}

		// Add upper 16 bits to lower 16 bits.

		sum = (sum >>> 16) + (sum & 0xffff);

		// Add carry

		sum += sum >>> 16;

		// Ones complement and truncate.

		return (short) ~sum;
	}
	
	private net.floodlightcontroller.core.IListener.Command sendACKAndRedirectGet(
			Ethernet eth, IPv4 ip, byte[] payloadData, TCP tcp, IOFSwitch sw, IPv4Address sourceAddress, int sourcePort, IPv4Address destinationAddress, int destinationPort) {

		//Block traffic from the Origin server before hand
		//To avoid any race conditions due to client retransmissions
//		blockSpecificTraffic(sw, destinationAddress, destinationPort, sourceAddress, sourcePort);

//		Maybe store GTP context here. The reverse context actually. 
//		Use the same ID as IP on gtp maybe
		
		TCP ackToBeSent = this.tcpContextAnalyzer.getACKFromTCPData(tcp);
		Ethernet ethtoSendACK = null;
		boolean isGTPTraffic = isGTPTraffic(eth);
		
		if(isGTPTraffic){
			logger.debug("Sending ACK for a GTP tunneled client...");
			ethtoSendACK = this.transportContextManager.reverseContextGTP(eth, ackToBeSent);
		} else {
			logger.debug("Sending ACK no GTP tunneled client...");
			ethtoSendACK = this.transportContextManager.reverseContext(eth, ackToBeSent);
		}
		
		logger.debug("First time sending ACK to sw "+sw);
		createAndSendPacketOut(sw, ethtoSendACK.serialize(),
				OFPort.FLOOD);
		
		//ACK sent to client
		//Now we need to request content from the cache
		
		String payloadString = new String(payloadData);
		Inet4Address localCacheAddress = this.getLocalCache(payloadString);
		int localCachePort = 80;
		
		logger.debug("HTTP GET detected, forwarding it to " + localCacheAddress);
		
		TCPIPConnection clientTCPIPId = new TCPIPConnection(sourceAddress, sourcePort);
		
		if(this.splicingClients.containsKey(clientTCPIPId)){
			logger.debug("DUP HTTP GET detected, dropping the get adr " +sourceAddress + " port "+sourcePort);

			//Already splicing so do nothing with this GET
			return Command.STOP;
		}
		
		SplicingInfo info = new SplicingInfo(sourceAddress, sourcePort, destinationAddress, destinationPort, sw, IPv4Address.of(localCacheAddress), localCachePort, tcp, eth.getSourceMACAddress(), eth.getDestinationMACAddress());
		
		info.setToClientTsValues(this.tcpContextAnalyzer.getTsValues(ackToBeSent));
		
		if(isGTPTraffic){
			info.registerGTPContext(ethtoSendACK);
			info.registerClientToCacheContext(eth);
		}

		TCP synToBeSent = this.tcpContextAnalyzer.getSYNFromTCPGet(tcp, info.getCachePort());
		Ethernet ethToSendSyn = info.getEthToCache(this.getLocalCacheMacAddress(info.getCacheAddress()), synToBeSent, info.getClientMacAddress());
		
		Set<DatapathId> swIds = switchService.getAllSwitchDpids();
		
		for (DatapathId datapathId : swIds) {
			createAndSendPacketOut(switchService.getSwitch(datapathId), ethToSendSyn.serialize(),
					OFPort.FLOOD);
		}
		info.setState(SplicingState.Sync);
		logger.debug("Adding client to splicing list "+clientTCPIPId);
		this.splicingClients.put(clientTCPIPId, info);
		
		return Command.STOP;

	}

	private boolean isGTPTraffic(Ethernet eth) {
		if (eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();
			
			if(ip.getProtocol().equals(IpProtocol.UDP)){
				UDP udp = (UDP) ip.getPayload();
				
				if (udp.getSourcePort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getDestinationPort().equals(UDP.GTP_CLIENT_PORT)) {
					return true;
				}
			}
		}
		return false;
	}

	private void blockSpecificTraffic(IOFSwitch sw,
			IPv4Address sourceAddress, int sourcePort,
			IPv4Address destinationAddress, int destinationPort) {
		
		logger.debug("Blocking traffic dstA="+destinationAddress+" dstP="+destinationPort+" srcA="+sourceAddress+" srcP="+sourcePort);
		OFFactory myFactory = sw.getOFFactory();

		Match opositMatch = myFactory
				.buildMatch()
				.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setMasked(
						MatchField.IPV4_SRC,
						IPv4AddressWithMask.of(sourceAddress,
								IPv4Address.ofCidrMaskLength(32)))
				.setMasked(
						MatchField.IPV4_DST,
						IPv4AddressWithMask.of(destinationAddress,
								IPv4Address.ofCidrMaskLength(32)))
				.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
				.setExact(MatchField.TCP_SRC, TransportPort.of(sourcePort))
				.setExact(MatchField.TCP_DST, TransportPort.of(destinationPort))
				.build();

		List<OFAction> actionList = new ArrayList<OFAction>();

		OFFlowMod flowMod = myFactory.buildFlowAdd().setMatch(opositMatch)
				.setActions(actionList).setHardTimeout(3600).setIdleTimeout(10)
				.setPriority(32768).build();
		sw.write(flowMod);
	}
	
	private String getLocalCacheMacAddress(IPv4Address localCacheAddress){
		return "52:54:00:0b:3d:54";
	}

	private Inet4Address getLocalCache(String payloadString) {
		//Temporary code getting the first cache.
		//In future versions we should check where the content really is in the list of local caches.
		
		for (Inet4Address iPv4Address : localCaches) {
			return iPv4Address;
		}
		
		return null;
	}
	
	private boolean isFromLocalCache(IPv4Address sourceAddress) {
		for (Inet4Address inetAddress : localCaches) {
			if(IPv4Address.of(inetAddress).equals(sourceAddress)){
				return true;
			}
		}
		
		return false;
	}

	private boolean checkGETToForeignHTTPServer(List<Inet4Address> localHttpCaches, IPv4 ip, byte[] bytes) {
		
		if (bytes.length > 0) {
			
			String dataIntoString = new String(bytes);
			if (dataIntoString.contains("GET")
					&& dataIntoString.contains("HTTP")
					&& dataIntoString.contains("mp4")) {
				logger.info("HTTP GET detected checking if it to known local HTTP cache Dst=" + ip.getDestinationAddress());

				for (Inet4Address localCache : localHttpCaches) {
					if(ip.getDestinationAddress().equals(IPv4Address.of(localCache))) {
						return false;
					}
				}
				
				return true;
			}
		}
		
		return false;
	}

	public static void createAndSendPacketOut(IOFSwitch sw,
			byte[] serializedData, OFPort outputPort) {
		OFPacketOut po = sw
				.getOFFactory()
				.buildPacketOut()
				/* mySwitch is some IOFSwitch object */
				.setData(serializedData)
				.setActions(
						Collections.singletonList((OFAction) sw.getOFFactory()
								.actions().output(outputPort, 0xffFFffFF)))
				.setInPort(OFPort.CONTROLLER).build();

		sw.write(po);
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		this.tcpContextAnalyzer = new TCPContextAnalyzer();
		this.transportContextManager = new TransportContext();
		this.splicingClients = new HashMap<TCPIPConnection, SplicingInfo>();
		this.switchService = context.getServiceImpl(IOFSwitchService.class);

		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		this.localCaches = new ArrayList<Inet4Address>();
		
		try {
			this.localCaches.add(((Inet4Address)Inet4Address.getByName("192.168.1.3")));
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		logger = LoggerFactory.getLogger(HTTPGETSplicerModule.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {

		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

	}
	
}
