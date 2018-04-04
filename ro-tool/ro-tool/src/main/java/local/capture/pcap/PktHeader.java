package local.capture.pcap;

/**
 * 
 */
public class PktHeader {
	
	/**
	 * マイクロ秒単位
	 */
	private long time;
	
	/**
	 * length of portion present 
	 */
	private int capLen;
	/**
	 * length this packet (off wire) 
	 */
	private int len;
	/**
	 * @return the time
	 */
	public long getTime() {
		return time;
	}
	/**
	 * @param time the time to set
	 */
	public void setTime(long time) {
		this.time = time;
	}
	/**
	 * @return the capLen
	 */
	public int getCapLen() {
		return capLen;
	}
	/**
	 * @param capLen the capLen to set
	 */
	public void setCapLen(int capLen) {
		this.capLen = capLen;
	}
	/**
	 * @return the len
	 */
	public int getLen() {
		return len;
	}
	/**
	 * @param len the len to set
	 */
	public void setLen(int len) {
		this.len = len;
	}

	
	
}
