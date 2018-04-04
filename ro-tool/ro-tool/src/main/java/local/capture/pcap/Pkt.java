package local.capture.pcap;

public class Pkt {
	private PktHeader header;
	private byte[] data;
	/**
	 * @return the header
	 */
	public PktHeader getHeader() {
		return header;
	}
	/**
	 * @param header the header to set
	 */
	public void setHeader(PktHeader header) {
		this.header = header;
	}
	/**
	 * @return the data
	 */
	public byte[] getData() {
		return data;
	}
	/**
	 * @param data the data to set
	 */
	public void setData(byte[] data) {
		this.data = data;
	}
}
