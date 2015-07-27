package net.floodlightcontroller.packet.gtp;


public abstract class AbstractGTPHeader implements IGTPHeader {
	
	public static final short GTP_FLAG_MASK = (1 << AbstractGTP.GTP_VERSION_SHIFT) - 1;
	protected byte version;
	
	
	protected byte[] createHeaderDataArray() {
		byte[] data = new byte[getSizeInBytes()];
		return data;
	}

	@Override
	public byte getVersion() {
		return this.version;
	}

	public abstract int getSizeInBytes();
	
	public abstract byte[] getNextSequenceNumber();

}
