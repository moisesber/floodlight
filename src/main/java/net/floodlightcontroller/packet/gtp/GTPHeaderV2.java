package net.floodlightcontroller.packet.gtp;

import java.nio.ByteBuffer;

public class GTPHeaderV2 extends AbstractGTPHeader {
	
	/**
	 * 
	 * GTPv2 as seen in 3GPP TS 29.274 V13.2.0 (2015-06)
	 * 
     * ------------------------------------------
     * |        Version (3)         |   P (1)   |
     * ------------------------------------------
     * |  T  (1)  |          Spare (3) [*]      | 
     * ------------------------------------------
     * |           Message Type (4)             |
     * ------------------------------------------
     * |            Length 1st (4)              |
     * ------------------------------------------
     * |            Length 2nd (4)              |
     * ------------------------------------------
     * | Tunnel Endpoint Identifier 1st (4) [1] |
     * ------------------------------------------
     * | Tunnel Endpoint Identifier 2nd (4) [1] |
     * ------------------------------------------
     * | Tunnel Endpoint Identifier 3rd (4) [1] |
     * ------------------------------------------
     * | Tunnel Endpoint Identifier 4th (4) [1] |
     * ------------------------------------------
     * |       Sequence Number 1st (4)          |
     * ------------------------------------------
     * |       Sequence Number 2nd (4)          |
     * ------------------------------------------
     * |       Sequence Number 3rd (4)          |
     * ------------------------------------------
     * |             Spare (4) [*]              |
     * ------------------------------------------
	 * 
 	 * NOTE 0:	[*] Spare bits.  The sender shall set them to "0" and the receiving entity shall ignore them.
	 * NOTE 1:	[1] This field will only exist and therefore shall only be evaluated when indicated by the T flag set to 1.
	 * 
     */
	
	//GTPv2 flags
	private int spareFlag;
	private boolean teidFlag;
	private boolean piggyBackingFlag;
	private byte[] sequenceNumberV2;
	private byte messageType;
	private short totalLength;
	private int teid;
	private byte spare;

	@Override
	public byte[] serialize() {
		byte[] data = createHeaderDataArray();
		
		ByteBuffer bb = ByteBuffer.wrap(data);
		byte flags = (byte) ((this.version << AbstractGTP.GTP_VERSION_SHIFT)
				+ (this.piggyBackingFlag ? 16 : 0) + (this.teidFlag ? 8 : 0)
				+ (this.spareFlag));
		
		bb.put(flags);
		bb.put(this.messageType);
		bb.putShort(this.totalLength);
		if(this.teidFlag){
			bb.putInt(this.teid);
		}
		
		for(int i=0; i<3;i++){
			bb.put(this.sequenceNumberV2[i]);	
		}
		bb.put(this.spare);
		
		return data;
	}

	@Override
	public IGTPHeader deserialize(ByteBuffer bb, byte scratch) {
		this.version = AbstractGTP.extractVersionFromScratch(scratch);
		
		byte flags = (byte) (scratch & GTP_FLAG_MASK);

		this.piggyBackingFlag = ((flags & 16) != 0);
		this.teidFlag = ((flags & 8) != 0);
		this.spareFlag = ((flags & 7));
		
		this.messageType = bb.get();
		this.totalLength = bb.getShort();
		
		if(this.teidFlag){
			this.teid = bb.getInt();
		}
		
		for(int i=0; i<3;i++){
			this.sequenceNumberV2[i] = bb.get();	
		}

		//No extension headers according to 3GPP TS 29.274 V13.2.0 (2015-06) Section 5.2
		//Spare last byte according to 3GPP TS 29.274 V13.2.0 (2015-06)
		this.spare = bb.get();
		return this;
	}

	@Override
	public int getSizeInBytes() {
	
		// Flags = 1
		// Message Type = 1
		// Length = 2
		// Sequence Number = 3
		// Spare
		int fixedHeaderSizeBytes = 1 + 1 + 2 + 3 + 1;
		
		if (this.teidFlag) {
			// teid = 4
			fixedHeaderSizeBytes += 4;
		}
		
		//No extension headers according to 3GPP TS 29.274 V13.2.0 (2015-06) Section 5.2
		
		return fixedHeaderSizeBytes;
	}
	
	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();

//	     * ------------------------------------------
//	     * |        Version (3)         |   P (1)   |
//	     * ------------------------------------------
//	     * |  T  (1)  |          Spare (3) [*]      | 

		buffer.append("\n");
		buffer.append("|Ver\t|Pgy\t|T\t|Spr[*]\t\n");

		buffer.append(this.version + "\t" + this.piggyBackingFlag + "\t"
				+ this.spareFlag + "\t\n");

		return buffer.toString();
	}

}
