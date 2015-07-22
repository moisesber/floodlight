package net.floodlightcontroller.packet.gtp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import net.floodlightcontroller.packet.BasePacket;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.PacketParsingException;

public class GTPHeaderV1 extends AbstractGTPHeader {
	
    /**
     * Got from 3GPP TS 29.060 V13.1.0 (2015-06) Section 6
     * GTPv1
     * ------------------------------------------
     * |V* (3)|PT (1)|[*] (1)|E (1)|S (1)|PN (1)|
     * ------------------------------------------
     * |           Message Type (8)             |
     * ------------------------------------------
     * |            Length 1st (8)              |
     * ------------------------------------------
     * |            Length 2nd (8)              |
     * ------------------------------------------
     * |   Tunnel Endpoint Identifier 1st (8)   |
     * ------------------------------------------
     * |   Tunnel Endpoint Identifier 2nd (8)   |
     * ------------------------------------------
     * |   Tunnel Endpoint Identifier 3rd (8)   |
     * ------------------------------------------
     * |   Tunnel Endpoint Identifier 4th (8)   |
     * ------------------------------------------
     * |       Sequence Number 1st (8)   [1][4] |
     * ------------------------------------------
     * |       Sequence Number 2nd (8)   [1][4] |
     * ------------------------------------------
     * |            N-PDU Number (8)     [2][4] |
     * ------------------------------------------
     * |  Next Extension Header Type (8) [3][4] |
     * ------------------------------------------
     * 
     * V* = Version
     * NOTE 0:	[*] This bit is a spare bit. It shall be sent as "0". The receiver shall not evaluate this bit.
	 * NOTE 1:	[1] This field shall only be evaluated when indicated by the S flag set to 1.
	 * NOTE 2:	[2] This field shall only be evaluated when indicated by the PN flag set to 1.
	 * NOTE 3:	[3] This field shall only be evaluated when indicated by the E flag set to 1.
	 * NOTE 4:	[4] This field shall be present if and only if any one or more of the S, PN and E flags are set.
	 **/
	
//	public static final byte GTP_PROTOCOL_TYPE_MASK = 16;
	
	//GTPv1 flags
	private boolean protocolType;
	private boolean reserved;
	private boolean extHeaderFlag;
	private boolean sequenceNumberFlag;
	private boolean nPDUNumberFlag;
	private byte messageType;
	private short totalLength;
	private int teid;
	private byte nextExtHeader;
	private byte nPDUNumber;
	private short sequenceNumber;
	private List<GTPExtHeader> extHeaders;
	
	public GTPHeaderV1(){
		extHeaders = new ArrayList<GTPExtHeader>();
	}

	@Override
	public byte[] serialize() {
		byte[] data = createHeaderDataArray();

		ByteBuffer bb = ByteBuffer.wrap(data);

		byte flags = (byte) ((this.version << AbstractGTP.GTP_VERSION_SHIFT)
				+ (this.protocolType ? 16 : 0) + (this.reserved ? 8 : 0)
				+ (this.extHeaderFlag ? 4 : 0)
				+ (this.sequenceNumberFlag ? 2 : 0) + (this.nPDUNumberFlag ? 1
				: 0));
		bb.put(flags);
		bb.putInt(this.messageType);
		bb.putShort(this.totalLength);
		bb.putInt(this.teid);

		if (this.extHeaderFlag || this.sequenceNumberFlag
				|| this.nPDUNumberFlag) {
			// Extra fields are present
			// They should be read, but interpreted only if
			// Specific flags are set
			bb.putShort(this.sequenceNumber);
			bb.put(this.nPDUNumber);
			bb.put(this.nextExtHeader);

			for (GTPExtHeader extHeader : extHeaders) {
				bb.put(extHeader.serialize());
			}
		}

		return data;
	}

	@Override
	public IGTPHeader deserialize(ByteBuffer bb, byte scratch) throws PacketParsingException {
		this.version = AbstractGTP.extractVersionFromScratch(scratch);

		byte flags = (byte) (scratch & GTP_FLAG_MASK);

		this.protocolType = ((flags & 16) != 0);
		this.reserved = ((flags & 8) != 0);
		this.extHeaderFlag = ((flags & 4) != 0);
		this.sequenceNumberFlag = ((flags & 2) != 0);
		this.nPDUNumberFlag = ((flags & 1) != 0);

		this.messageType = bb.get();
		this.totalLength = bb.getShort();

		this.teid = bb.getInt();

		if (this.extHeaderFlag || this.sequenceNumberFlag
				|| this.nPDUNumberFlag) {
			// Extra fields are present
			// They should be read, but interpreted only if
			// Specific flags are set
			short seqNumber = bb.getShort();
			byte nPDUNum = bb.get();
			byte nextHeader = bb.get();

			if (this.sequenceNumberFlag) {
				this.sequenceNumber = seqNumber;
			}

			if (this.nPDUNumberFlag) {
				this.nPDUNumber = nPDUNum;
			}

			if (this.extHeaderFlag) {
				this.nextExtHeader = nextHeader;
				extHeaders = new ArrayList<GTPExtHeader>();
			}

			while (nextHeader != 0) {
				// This means that there are extra headers to be read

				GTPExtHeader extHeader = new GTPExtHeader();
				extHeader.setVersion(this.version);
//				extHeader.deserialize(bb.array(), bb.position(),
//						bb.limit() - bb.position());
				extHeader.deserialize(bb, (byte) 0);
				extHeaders.add(extHeader);
				nextHeader = extHeader.getNextExtHeaderType();
			}
		}
		
		return this;
	}

	@Override
	public int getSizeInBytes() {

		// Flags = 1
		// Message Type = 1
		// Length = 2
		// teid = 4
		int fixedHeaderSizeBytes = 1 + 1 + 2 + 4;
		if (this.extHeaderFlag || this.sequenceNumberFlag
				|| this.nPDUNumberFlag) {
			
			// Sequence Number = 2
			// N-PDU number = 1
			// Next Extension Header = 1
			fixedHeaderSizeBytes += 2 + 1 + 1;
		}
		
		int numberOfExtraBytes = 0;
		for (GTPExtHeader extHeader : extHeaders) {
			numberOfExtraBytes += extHeader.getN();
		}

		return fixedHeaderSizeBytes + numberOfExtraBytes;
	}
	
	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();

		// * ----------------------------------------------------------
		// * | Version (3) | PT (1) | [*] (1) | E (1) | S (1) | PN (1) |
		// * ----------------------------------------------------------
		// * 

		buffer.append("\n");
		buffer.append("|Ver\t|PT\t|(*)\t|E\t|S\t|PN\t|\n");

		buffer.append(this.version + "\t" + this.protocolType + "\t"
				+ this.reserved + "\t" + this.extHeaderFlag + "\t"
				+ this.sequenceNumberFlag + "\t" + this.nPDUNumberFlag+"\n");

		return buffer.toString();
	}
	
	
	class GTPExtHeader implements IGTPHeader {

		private byte n;
		private byte nextExtHeaderType;
		private IPacket payload;
		private byte version;

		public byte getN() {
			return n;
		}

		public void setVersion(byte version) {
			this.version = version;
		}

		public byte getNextExtHeaderType() {
			return nextExtHeaderType;
		}

		@Override
		public byte[] serialize() {
			byte[] data = new byte[(this.n*4)];
			data[0] = this.n;
			
			byte[] headerData = ((Data)this.payload).getData();
			
			for (int i = 1; i < this.n*4; i++) {
				data[i] = headerData[i-1];
			}

			return data;
		}
		
		public IPacket getExtraHeader(){
			return this.payload;
		}

		public IGTPHeader deserialize(byte[] data, int offset, int length)
				throws PacketParsingException {
			
	        ByteBuffer bb = ByteBuffer.wrap(data, offset, length);
	        
	        return deserialize(bb, (byte) 0);
		}

		@Override
		public IGTPHeader deserialize(ByteBuffer bb, byte scratch)
				throws PacketParsingException {
			//The number of octets according to 3GPP TS 29.060 V13.1.0 (2015-06) Section 6
	        //The total number of octets, including the this.n, is this.n * 4
			this.n = bb.get();
			byte[] headerData = new byte[(this.n*4)-1];
			
			//Read all extra information according to this.n
			for (int i = 1; i < this.n*4; i++) {
				headerData[i-1] = bb.get();
			}
			
			this.nextExtHeaderType = headerData[headerData.length-1];

			this.payload = new Data(headerData);
			return this;
		}

		@Override
		public byte getVersion() {
			return this.version;
		}

		@Override
		public int getSizeInBytes() {
			return this.n;
		}

	}

}
