package local.capture.pcap;

import com.sun.jna.Pointer;

public class PcapException extends Exception{
	private static final long serialVersionUID = -5178321300274138973L;
	private int code;
	
	
	public PcapException(int code, Pointer errbuf) {
		this(code, errbuf.getString(0));
	}
	
	public PcapException(int code, String message) {
		super(message + "(" + code + ")");
		this.code = code;
	}
	
	public PcapException(Pointer errbuf) {
		this(errbuf.getString(0));
	}
	
	public PcapException(String message) {
		super(message);
	}

	/**
	 * @return the code
	 */
	public int getCode() {
		return code;
	}
	
	
}
