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

import com.google.common.primitives.UnsignedInteger;
import com.google.common.primitives.UnsignedInts;

public class HTTPGETSplicerModule implements IFloodlightModule, IOFMessageListener {
	
	
	class IPIDTag {
		
		IPv4Address sourceAddress;
		
	}
	
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
//	private Map<Integer, TCPClient> connectedDummyClients;
//	private Map<IPv4Address, Map<Integer, TCPSectionContext>> payloadContext;
	private List<Inet4Address> localCaches;
	private TCPContextAnalyzer tcpContextAnalyzer;
	private Map<IPv4Address, Short> lastIDFromIPSource;
	private Map<TCPIPConnection, SplicingInfo> splicingClients;


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
		logger.warn("Packet In...");

//		OFPacketIn pin = (OFPacketIn) msg;
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		if (eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();

			if (ip.getProtocol().equals(IpProtocol.TCP)) {
				TCP tcp = (TCP) ip.getPayload();
				
				
				//Registering all TCP traffic for now.
				//In the future, we should restrict to only TCP traffic to 
				//port 80 and to destinationAddress == oneOfTheknownHTTPServers

				int sourcePort = tcp.getSourcePort().getPort();
				IPv4Address sourceAddress = ip.getSourceAddress();
				int destinationPort = tcp.getDestinationPort().getPort();
				IPv4Address destinationAddress = ip.getDestinationAddress();
				
				TCPIPConnection sourceTCPIPId = new TCPIPConnection(sourceAddress, sourcePort);
				TCPIPConnection dstTCPIPId = new TCPIPConnection(destinationAddress, destinationPort);

				this.lastIDFromIPSource.put(sourceAddress, ip.getIdentification());
				

				
				if(isFromLocalCache(sourceAddress)){
					//Content from local cache
					logger.warn("Receiving something from cache "+sourceAddress+" destination is "+dstTCPIPId);
					
					if(this.splicingClients.containsKey(dstTCPIPId)){
						SplicingInfo info = this.splicingClients.get(dstTCPIPId);
						
						logger.warn("From cache and destination is a splicing client "+dstTCPIPId+" splicing state = "+info.getState());
						
						if(info.getState().equals(SplicingState.Connected)){
							Ethernet cloneEth = (Ethernet)eth.clone();
							IPv4 cloneIP = (IPv4)ip.clone();
							TCP cloneTCP = (TCP)tcp.clone();

							cloneIP.setSourceAddress(info.getOriginAddress());
							cloneTCP.setSourcePort(info.getOriginPort());
							
							logger.warn("Before it was Seq="+cloneTCP.getSequence());

							try{
								UnsignedInteger tcpSeq = UnsignedInteger.asUnsigned(tcp.getSequence());
								UnsignedInteger initialSeqFromSYNACK = UnsignedInteger.asUnsigned(info.getInitialSEQFromSYNACK());
								UnsignedInteger initialOriginSeq = UnsignedInteger.asUnsigned(info.getInitialOriginSequenceNumber());
								int seq = tcpSeq.subtract(initialSeqFromSYNACK).add(initialOriginSeq).subtract(UnsignedInteger.ONE).intValue();

//								int seq = (tcp.getSequence() - info.getInitialSEQFromSYNACK()) + info.getInitialOriginSequenceNumber() - 1; 
								cloneTCP.setSequence(seq);
							} catch (IllegalArgumentException e){
								e.printStackTrace();
							}
							logger.warn("After it was Seq="+cloneTCP.getSequence());

							byte[] options = this.tcpContextAnalyzer.getOptionsWithNewTsValues(info.getToClientTSValue(), info.getToClientTSecr(), tcp.getOptions());
							cloneTCP.setOptions(options);

							cloneEth.setDestinationMACAddress(info.getClientMacAddress());
							cloneEth.setSourceMACAddress(info.getOriginMacAddress());
							
							cloneIP.setPayload(cloneTCP);
							cloneTCP.setParent(cloneIP);
							cloneEth.setPayload(cloneIP);
							cloneIP.setParent(cloneEth);

							
							short before = cloneTCP.getChecksum();
							cloneTCP.resetChecksum();
							cloneTCP.serialize();
							short once = cloneTCP.getChecksum();
							cloneTCP.resetChecksum();
							cloneTCP.serialize();
							short twice = cloneTCP.getChecksum();
							
							short[] checksums = this.getChecksum(cloneTCP);

							if(once != twice || once != checksums[2]){
								logger.warn("different checksums!!! @#@#@$$@$@$");
							}
							
							cloneTCP.setChecksum(checksums[2]);
							
							

							
							logger.warn("Reseting the checksum to splicing client "+dstTCPIPId+" splicing state = "+info.getState()+" Ocks="+Integer.toHexString(tcp.getChecksum())+ " before="+Integer.toHexString(before)+" once="+Integer.toHexString(once)+" twice="+Integer.toHexString(twice));
//							logger.warn("floodlight "+Integer.toHexString(checksums[0]));
//							logger.warn("normalChec "+Integer.toHexString(checksums[1]));
//							logger.warn("specificCh "+Integer.toHexString(checksums[2]));
							
							
							createAndSendPacketOut(info.getClientSw(), cloneEth.serialize(),
									OFPort.FLOOD);
							
							return Command.STOP;
						}
						
						if(this.tcpContextAnalyzer.checkIfACKReceived(tcp)){
							
							if(info.getState().equals(SplicingState.Sync)){
								info.setState(SplicingState.Connected);
								return Command.STOP;
							}
							
						}

						if(this.tcpContextAnalyzer.checkIfSYNACKReceived(tcp)){

							if(!info.getState().equals(SplicingState.Sync)){
								logger.warn("Receiving a SYNACK for a connectiong already connected or not in Sync, something when wrong... "+info.getClientAddress()+ " "+info.getClientPort());
								return Command.STOP;
							}
							
							logger.warn("Receiving SYNACK from cache and destination is a splicing client, sending ACK");

							TCP ackToBeSent = this.tcpContextAnalyzer.getACKFromSYNACK(tcp);
//							Ethernet ethtoSendACK = (new TransportContext(eth)).reverseContext(this.lastIDFromIPSource.get(sourceAddress), ackToBeSent);
							Ethernet ethtoSendACK = (new TransportContext(eth)).reverseContext((short)0, ackToBeSent);

							
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
							
//							Ethernet ethtoSendGET = (new TransportContext(eth)).reverseContext(this.lastIDFromIPSource.get(sourceAddress), get);
							Ethernet ethtoSendGET = (new TransportContext(eth)).reverseContext((short)0, get);

							
							createAndSendPacketOut(sw, ethtoSendGET.serialize(),
									OFPort.FLOOD);
							
							return Command.STOP;
						}
						
						
						
						
					}
				}
				
				Data tcpData = (Data)tcp.getPayload();
				byte[] bytes = tcpData.getData();
				if(this.splicingClients.containsKey(sourceTCPIPId)){
					SplicingInfo info = this.splicingClients.get(sourceTCPIPId);

					if(info.getState().equals(SplicingState.Connected)){
						if(bytes.length == 0){
							
							if(this.tcpContextAnalyzer.checkIfACKReceived(tcp)){
								//Control data from client to server being spliced
								//Redirect the data and send it
								
								ip.setDestinationAddress(info.getCacheAddress());
								tcp.setDestinationPort(info.getCachePort());
								eth.setSourceMACAddress(info.getClientMacAddress());
								eth.setDestinationMACAddress(this.getLocalCacheMacAddress(info.getCacheAddress()));
								
								logger.warn("Before it was Ack="+tcp.getAcknowledge());

								UnsignedInteger tcpSeq = UnsignedInteger.asUnsigned(tcp.getAcknowledge());
								UnsignedInteger initialSeqFromSYNACK = UnsignedInteger.asUnsigned(info.getInitialSEQFromSYNACK());
								UnsignedInteger initialOriginSeq = UnsignedInteger.asUnsigned(info.getInitialOriginSequenceNumber());
								int ack = tcpSeq.subtract(initialOriginSeq).add(initialSeqFromSYNACK).add(UnsignedInteger.ONE).intValue();
								
//								int ack = (tcp.getAcknowledge() - info.getInitialOriginSequenceNumber()) + info.getInitialSEQFromSYNACK() + 1; 
								tcp.setAcknowledge(ack);
								logger.warn("After it was Ack="+tcp.getAcknowledge());

								tcp.resetChecksum();
								
								createAndSendPacketOut(info.getCacheSw(), eth.serialize(),
										OFPort.FLOOD);
							} else if(this.tcpContextAnalyzer.checkIfRSTReceived(tcp)){
								ip.setDestinationAddress(info.getCacheAddress());
								tcp.setDestinationPort(info.getCachePort());
								eth.setSourceMACAddress(info.getClientMacAddress());
								eth.setDestinationMACAddress(this.getLocalCacheMacAddress(info.getCacheAddress()));
								
								UnsignedInteger tcpSeq = UnsignedInteger.asUnsigned(tcp.getAcknowledge());
								UnsignedInteger initialSeqFromSYNACK = UnsignedInteger.asUnsigned(info.getInitialSEQFromSYNACK());
								UnsignedInteger initialOriginSeq = UnsignedInteger.asUnsigned(info.getInitialOriginSequenceNumber());
								int ack = tcpSeq.subtract(initialOriginSeq).add(initialSeqFromSYNACK).add(UnsignedInteger.ONE).intValue();
								
//								int ack = (tcp.getAcknowledge() - info.getInitialOriginSequenceNumber()) + info.getInitialSEQFromSYNACK() + 1; 
								tcp.setAcknowledge(ack);
								
								tcp.resetChecksum();
								
								createAndSendPacketOut(info.getCacheSw(), eth.serialize(),
										OFPort.FLOOD);
							}

						
						}
					}
					
					return Command.STOP;
				}

				
				boolean isGetMethodForKnownHttpServer = this.checkGETToForeignHTTPServer(localCaches, ip, bytes);
				
				if(isGetMethodForKnownHttpServer){
					return sendACKAndRedirectGet(eth, ip, bytes, tcp, sw, sourceAddress, sourcePort, destinationAddress, destinationPort);
				}				
				
			}
		}

		return Command.CONTINUE;
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
	
	static long integralFromBytes(byte[] buffer, int offset, int length) {

		long answer = 0;

		while (--length >= 0) {
			answer = answer << 8;
			answer |= buffer[offset] >= 0 ? buffer[offset]
					: 0xffffff00 ^ buffer[offset];
			++offset;
		}

		return answer;
	}

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

	public static void shortToBytes(short value, byte[] buffer, int offset) {
		buffer[offset + 1] = (byte) (value & 0xff);
		value = (short) (value >> 8);
		buffer[offset] = (byte) (value);
	}
	

	private net.floodlightcontroller.core.IListener.Command sendACKAndRedirectGet(
			Ethernet eth, IPv4 ip, byte[] payloadData, TCP tcp, IOFSwitch sw, IPv4Address sourceAddress, int sourcePort, IPv4Address destinationAddress, int destinationPort) {

		TCP ackToBeSent = this.tcpContextAnalyzer.getACKFromTCPData(tcp);
//		short lastIDFromOrigin = this.lastIDFromIPSource.get(ip.getDestinationAddress());
		short lastIDFromOrigin = (short)0;
		
		Ethernet ethtoSendACK = (new TransportContext(eth)).reverseContext(lastIDFromOrigin, ackToBeSent);
		
		createAndSendPacketOut(sw, ethtoSendACK.serialize(),
				OFPort.FLOOD);
		
		//ACK sent to client
		//Now we need to request content from the cache
		
		String payloadString = new String(payloadData);
		Inet4Address localCacheAddress = this.getLocalCache(payloadString);
		int localCachePort = 80;
		
		logger.warn("HTTP GET detected, forwarding it to " + localCacheAddress);
		
		TCPIPConnection clientTCPIPId = new TCPIPConnection(sourceAddress, sourcePort);
		
		if(this.splicingClients.containsKey(clientTCPIPId)){
			
			//Already splicing so do nothing with this GET
			return Command.STOP;
		}
		
		SplicingInfo info = new SplicingInfo(sourceAddress, sourcePort, destinationAddress, destinationPort, sw, IPv4Address.of(localCacheAddress), localCachePort, tcp, eth.getSourceMACAddress(), eth.getDestinationMACAddress());
		
		info.setToClientTsValues(this.tcpContextAnalyzer.getTsValues(ackToBeSent));
//		info.setInitialIDFromOrigin(lastIDFromOrigin);

		TCP synToBeSent = this.tcpContextAnalyzer.getSYNFromTCPGet(tcp, info.getCachePort());
		Ethernet ethToSendSyn = info.getEthToCache(this.getLocalCacheMacAddress(info.getCacheAddress()), synToBeSent, info.getClientMacAddress());
		
		Set<DatapathId> swIds = switchService.getAllSwitchDpids();
		
		for (DatapathId datapathId : swIds) {
			createAndSendPacketOut(switchService.getSwitch(datapathId), ethToSendSyn.serialize(),
					OFPort.FLOOD);
		}
		info.setState(SplicingState.Sync);
		logger.warn("Adding client to splicing list "+clientTCPIPId);
		this.splicingClients.put(clientTCPIPId, info);
		blockSpecificTraffic(sw, destinationAddress, destinationPort, sourceAddress, sourcePort);
		
		return Command.STOP;


//		TCPSectionContext ackPayloadContext = null;
//
//		if (this.payloadContext.containsKey(destinationAddress)) {
//			Map<Integer, TCPSectionContext> map = this.payloadContext
//					.get(destinationAddress);
//
//			if (map.containsKey(destinationPort)) {
//				ackPayloadContext = map.get(destinationPort);
//			}
//		}
//
//		if (ackPayloadContext == null) {
//			throw new RuntimeException(
//					"No previous payload for this tunnel, trying to splice a new connection?");
//		}
//
//		TCPSectionContext getPayloadContext = new TCPSectionContext();
////		getPayloadContext.setReversePath(ackPayloadContext);
//		getPayloadContext.updateContext(ip, sw);
//
//		
//		
//		IPv4 ackGTPIp = ackPayloadContext.getACK(payloadData.length,
//				getPayloadContext.getTsVal(), getPayloadContext.getTsecr());
//
//		Ethernet ack = ackPayloadContext.getDataLayerContext()
//				.getPacketWithPayload(ackGTPIp);
//
//		createAndSendPacketOut(ackPayloadContext.getSw(), ack.serialize(),
//				OFPort.FLOOD);
//
//		blockSpecificTraffic(sw, destinationAddress, destinationPort, sourceAddress, sourcePort);
////		blockSpecificTraffic(sw, sourceAddress, sourcePort, destinationAddress, destinationPort);
//
//		
//
//		boolean alreadyDownloadingThisData = this.checkDummyClients(
//				sourceAddress, sourcePort) != null;
//		logger.warn("TESTING! Previous client for " + sourceAddress + " "
//				+ sourcePort + " r=" + alreadyDownloadingThisData);
//
//		if (!alreadyDownloadingThisData) {
//			logger.warn("CONFIRMED! No previous client for " + sourceAddress
//					+ " " + sourcePort);
//
//			DummyHTTPClient dummyClient = new DummyHTTPClient(
//					localCacheAddress, 80, payloadString, sourceAddress, sourcePort,
//					destinationAddress, destinationPort);
//			dummyClient.addClientListener(this);
//			Thread t = new Thread(dummyClient);
//			t.start();
//		}
//
//		return Command.STOP;

	}

//	private int getAvailablePort() {
//		int possiblePort = 1024;
//		
//		while(possiblePort < 65535){
//		    Socket s = null;
//		    try {
//		        s = new Socket("localhost", possiblePort);
//		        possiblePort++;
//		    } catch (IOException e) {
//		        return possiblePort;
//		    } finally {
//		        if( s != null){
//		            try {
//		                s.close();
//		            } catch (IOException e) {
//		                throw new RuntimeException("Problems trying to find a local available port." , e);
//		            }
//		        }
//		    }
//		}
//		
//        throw new RuntimeException("Unable to find a local port.");
//	}

	private void blockSpecificTraffic(IOFSwitch sw,
			IPv4Address destinationAddress, int destinationPort,
			IPv4Address sourceAddress, int sourcePort) {
		OFFactory myFactory = sw.getOFFactory();

		Match opositMatch = myFactory
				.buildMatch()
				.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setMasked(
						MatchField.IPV4_SRC,
						IPv4AddressWithMask.of(destinationAddress,
								IPv4Address.ofCidrMaskLength(32)))
				.setMasked(
						MatchField.IPV4_DST,
						IPv4AddressWithMask.of(sourceAddress,
								IPv4Address.ofCidrMaskLength(32)))
				.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
				.setExact(MatchField.TCP_SRC, TransportPort.of(destinationPort))
				.setExact(MatchField.TCP_DST, TransportPort.of(sourcePort))
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
				logger.warn("HTTP GET detected checking if it to known local HTTP cache Dst=" + ip.getDestinationAddress());

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

//	private Command spliceAndRedirectLocalTraffic(TCP tcp, byte[] bytes) {
//		int localPort = tcp.getDestinationPort()
//				.getPort();
//		
//		TCPClient dummyClient = this.connectedDummyClients
//				.get(localPort);
//
//		TCPSectionContext httpPayloadContext = null;
//		IPv4Address destinationAddress = dummyClient
//				.getDestinationAddress();
//		int tcpDstPort = dummyClient
//				.getDestinationPort();
//
//		if (this.payloadContext
//				.containsKey(destinationAddress)) {
//			Map<Integer, TCPSectionContext> map = this.payloadContext
//					.get(destinationAddress);
//
//			if (map.containsKey(tcpDstPort)) {
//				httpPayloadContext = map
//						.get(tcpDstPort);
//			}
//		}
//
//		if (httpPayloadContext == null) {
//			throw new RuntimeException(
//					"No previous payload for this tunnel, trying to splice a new connection?");
//		}
//
//		logger.warn("TCP Flags = "+tcp.getFlags()+" RST ? "+ (tcp.getFlags() == TCPSectionContext.RST_FLAG) +" ACK ? "+(tcp.getFlags() == TCPSectionContext.ACK_FLAG));
//		logger.warn("Redirecting splicing traffic from localPort = "+localPort+" to A="+dummyClient.getSourceAddress()+" P="+dummyClient.getSourcePort());
////		Data data = (Data) tcp.getPayload();
////		byte[] bytes = data.getData();
////
////		if (bytes.length > 0) {
////			String originalMessage = new String(
////					bytes);
////			bytes = originalMessage.replace(
////					"video", "vedio").getBytes();
////
////			String s = new String(bytes);
////			logger.warn("Size = " + bytes.length
////					+ "\n" + s);
////			tcp.setPayload(new Data(bytes));
////		} else {
////			logger.warn("TCP payload "
////					+ bytes.length
////					+ " control traffic, no data to be sent.");
////			return Command.CONTINUE;
////		}
//		
//		
//		
//		
//		httpPayloadContext.addDataToBeSpliced(tcp, bytes.length);
//		
//		
//
////		IPv4 httpGTPed = httpPayloadContext
////				.getTunneledPayloadOf(tcp, bytes);
////
////		Ethernet httpData = httpPayloadContext
////				.getDataLayerContext()
////				.getPacketWithPayload(httpGTPed);
//
////		createAndSendPacketOut(
////				httpPayloadContext.getSw(),
////				httpData.serialize(), OFPort.FLOOD);
//
//		return Command.CONTINUE;
//	}

//	private boolean checkIfTrafficIsLocal(IPv4 ip) {
//		TCP tcp = (TCP) ip.getPayload();
//		
//		try {
//			Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
//			for (NetworkInterface netint : Collections.list(nets)) {
//				Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
//
//				for (InetAddress inetAddress : Collections.list(inetAddresses)) {
//					if (ip.getDestinationAddress().equals(IPv4Address.of(inetAddress))) {
//						logger.warn("Local IP found, checking port "+ tcp.getDestinationPort().getPort());
//
//						if (this.connectedDummyClients.containsKey(tcp.getDestinationPort().getPort())) {
//							return true;
//						}
//					}
//				}
//
//			}
//		} catch (SocketException e) {
//			logger.warn("Problems listing local interfaces/addresses. "+e.getMessage());
//		}
//		return false;
//	}

//	private TCPClient checkDummyClients(IPv4Address iPv4Address, int port) {
//		Set<Integer> localPorts = this.connectedDummyClients.keySet();
//		for (int localPort : localPorts) {
//			TCPClient client = this.connectedDummyClients.get(localPort);
//
//			// System.out.println("Checking " + client.getSourceAddress() + "=="
//			// + iPv4Address);
//			// System.out.println("Checking " + client.getLocalPort() + "=="
//			// + port);
//
//			if (client.getSourceAddress().equals(iPv4Address)
//					&& client.getSourcePort() == port) {
//				return client;
//			}
//		}
//		return null;
//	}

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
		this.lastIDFromIPSource = Collections.synchronizedMap(new HashMap<IPv4Address, Short>());
		this.splicingClients = new HashMap<TCPIPConnection, SplicingInfo>();
		this.switchService = context.getServiceImpl(IOFSwitchService.class);

//		this.connectedDummyClients = new HashMap<Integer, TCPClient>();
//		this.payloadContext = new HashMap<IPv4Address, Map<Integer, TCPSectionContext>>();
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
	
//	@Override
//	public void addConnectedClient(int localPort, TCPClient tcpClient) {
//		this.connectedDummyClients.put(localPort, tcpClient);
//	}
//
//	public void delConnectedDummyClient(int localPort) {
//		if (this.connectedDummyClients.containsKey(localPort)) {
//			// TODO REMOVE Client from this list
//			// while the client is on this list the connection is considered active
//			this.connectedDummyClients.remove(localPort);
//		}
//	}

}
