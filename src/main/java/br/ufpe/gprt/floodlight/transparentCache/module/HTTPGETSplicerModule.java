package br.ufpe.gprt.floodlight.transparentCache.module;

import java.net.Inet4Address;
import java.net.UnknownHostException;
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
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.gtp.AbstractGTP;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.ufpe.gprt.floodlight.transparentCache.properties.TCacheProperties;
import br.ufpe.gprt.floodlight.transparentCache.util.DelayLogger;

public class HTTPGETSplicerModule implements IFloodlightModule, IOFMessageListener {
	
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	private List<Inet4Address> localCaches;
	private TCPContextAnalyzer tcpContextAnalyzer;
	private TransportContext transportContextManager;
	private Map<TCPIPConnection, SplicingInfo> splicingClients;
	private long initialTimeStamp;
	private TCacheProperties properties;
	private DelayLogger delayLogger;


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
		
		if(this.properties.isDelayLoggingEnabled()){
			this.initialTimeStamp = System.currentTimeMillis();
		}
		
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
					
					
					if(this.tcpContextAnalyzer.checkIfFINACKReceived(tcp)){
						//Local cache trying to end the connection
						info.setState(SplicingState.Sync);
					} else if(this.tcpContextAnalyzer.checkIfFINPSHACKReceived(tcp)){
						//Specific Apache util ab behavior
						//Only used in our experiments
//						Data payload = (Data)tcp.getPayload();
//						int seq = tcp.getSequence();
//						
//						tcp.setSequence(seq  + payload.getData().length);
//						tcp.setAcknowledge(tcp.getAcknowledge());
//						
//						tcp.setFlags(TCPContextAnalyzer.FIN_ACK_FLAG);
//						
//						Data zero = new Data(new byte[0]);
//						tcp.setPayload(zero);
//						zero.setParent(tcp);
//						
//						tcp.resetChecksum();
//						Ethernet extraPacket = null;
//						if(!info.isGTPTunneled()){
//							extraPacket = eth;
//						} else {
//							extraPacket = info.getGtpContext().getTunneledData(ip, tcp);
//						}
//
//						logger.debug("Sending extra packet due to FIN PSH ACK received "+info.getClientSw());
//						createAndSendPacketOut(info.getClientSw(), extraPacket.serialize(),
//									OFPort.FLOOD);

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
					sendDataToClient(eth, ip, tcp, dstTCPIPId, info);
					
					if(this.tcpContextAnalyzer.checkIfACKReceived(tcp)){
						
						info.setState(SplicingState.Connected);
						this.logConnectionDelay(System.currentTimeMillis(), info);

						return Command.STOP;
					}
					
					if(this.tcpContextAnalyzer.checkIfFINACKReceived(tcp)){

						info.setState(SplicingState.Disconnecting);
						return Command.STOP;
					}
				} else if(info.getState().equals(SplicingState.Disconnecting)){
					sendDataToClient(eth, ip, tcp, dstTCPIPId, info);

					//This means that the cache server sent a FYN ACK packet to the client
					if(this.tcpContextAnalyzer.checkIfACKReceived(tcp)){

						info.setState(SplicingState.Disconnected);
						

						//Removed the splicing client from list of clients
						logger.debug("Cache server sending ACK to the FYN ACK answer from the client, connection closed and info removed. Befor Total splicing clients= "+this.splicingClients.size());

						this.splicingClients.remove(dstTCPIPId);
						logger.info("Cache server sending ACK to the FYN ACK answer from the client, connection closed and info removed. After Total splicing clients= "+this.splicingClients.size());
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
				if(this.tcpContextAnalyzer.checkIfFINACKReceived(tcp)){
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
					logger.debug("Client sending ACK to the FYN ACK answer from the cache server, connection closed and info removed. Befor Total splicing clients= "+this.splicingClients.size());

					this.splicingClients.remove(sourceTCPIPId);
					logger.info("Client sending ACK to the FYN ACK answer from the cache server, connection closed and info removed. After Total splicing clients= "+this.splicingClients.size());
					info.setState(SplicingState.Disconnected);
				}
			} else if(info.getState().equals(SplicingState.Sync)){
//						redirectDataFromClientToCache(eth, ip, tcp, info);
				
				if(this.tcpContextAnalyzer.checkIfFINACKReceived(tcp)){
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
		this.logOverheadDelay(System.currentTimeMillis(), info.isGTPTunneled());
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
			
			
			
			Ethernet ethernet = info.getGtpContext().getTunneledData(cloneIP, cloneTCP);
			logger.debug("Sending fragmented data to sw "+info.getClientSw());
			createAndSendPacketOut(info.getClientSw(), ethernet.serialize(),
						OFPort.FLOOD);
			this.logOverheadDelay(System.currentTimeMillis(), true);

			return ;
			
		}
		

		
		

		
		logger.debug("Sending data to sw "+info.getClientSw());
		createAndSendPacketOut(info.getClientSw(), cloneEth.serialize(),
				OFPort.FLOOD);
		this.logOverheadDelay(System.currentTimeMillis(), false);
	}
	
	private void logConnectionDelay(long currentTime, SplicingInfo info){
		if(this.properties.isDelayLoggingEnabled()){
			String protocol = "TCP";
			
			if(info.isGTPTunneled()){
				protocol = "GTP";
			}
			
			this.delayLogger.addDataToBuffer("SynDelay["+protocol+"] "+(currentTime - info.getSynTimeStamp()));
		}
	}
	
	private void logOverheadDelay(long currentTime, boolean gtp){
		if(this.properties.isDelayLoggingEnabled()){
			String protocol = "TCP";
			
			if(gtp){
				protocol = "GTP";
			}
			
			this.delayLogger.addDataToBuffer("OvhDelay["+protocol+"] "+(currentTime - this.initialTimeStamp));
		}
	}
	
	private net.floodlightcontroller.core.IListener.Command sendACKAndRedirectGet(
			Ethernet eth, IPv4 ip, byte[] payloadData, TCP tcp, IOFSwitch sw, IPv4Address sourceAddress, int sourcePort, IPv4Address destinationAddress, int destinationPort) {

		//Block traffic from the Origin server before hand
		//To avoid any race conditions due to client retransmissions
//		blockSpecificTraffic(sw, destinationAddress, destinationPort, sourceAddress, sourcePort);

//		Maybe store GTP context here. The reverse context actually. 
//		Use the same ID as IP on gtp maybe
		long  splicingTimeStamp = System.currentTimeMillis();
		
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
		
		long  synTimeStamp = System.currentTimeMillis();
		info.setState(SplicingState.Sync);
		logger.debug("Adding client to splicing list "+clientTCPIPId);
		info.setSynTimeStamp(synTimeStamp);
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

	private String getLocalCacheMacAddress(IPv4Address localCacheAddress){
		return TCacheProperties.getInstance().getCacheMacAddress();
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
		logger.debug("Checking if new traffic is GET and not for local cache Dst=" + ip.getDestinationAddress());

		if (bytes.length > 0) {
			
			String dataIntoString = new String(bytes);
			if (dataIntoString.contains("GET")
					&& dataIntoString.contains("HTTP")
					&& ( dataIntoString.contains("mp4") || dataIntoString.contains("m4s") )) {
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
		this.properties = TCacheProperties.getInstance();
		logger = LoggerFactory.getLogger(HTTPGETSplicerModule.class);
		
		if(this.properties.isDelayLoggingEnabled()){
			logger.info("Starting the Delay Logger.");
			this.delayLogger = new DelayLogger();
			Thread t = new Thread(this.delayLogger);
			t.start();
		}
		
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		this.localCaches = new ArrayList<Inet4Address>();
		
		try {
			this.localCaches.add(((Inet4Address)Inet4Address.getByName(this.properties.getCacheAddress())));
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {

		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

	}
	
}
