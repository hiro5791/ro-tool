package local.capture.pcap.jnr;

import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

public class timeval extends Structure{
	public static final List<String> FIELDS = createFieldsOrder("tv_sec", "tv_usec");
	
	/**
	 * tv_sec ： 指定する時間の1秒以上の部分（秒単位）
	 * tv_usec ： 指定する時間の1秒未満の部分（マイクロ秒単位）
	 */
	public int tv_sec;
	public int tv_usec;

	public timeval() {
		super();
	}

	public timeval(Pointer p) {
		super(p);
		read();
	}
	
	@Override
    protected List<String> getFieldOrder() {
        return FIELDS;
    }
}
