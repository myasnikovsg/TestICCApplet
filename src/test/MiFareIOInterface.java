package test;
/**
 * @author Hedin
 * Interface to grant access for TestApplet data. 
 */
import javacard.framework.Shareable;

public interface MiFareIOInterface extends Shareable {
	/**
	 * SIO method to write block. If client is eligible to perform this
	 * operation, this method will copy BLOCK_LENGTH bytes from buffer starting
	 * from offset to internal image at specified sector and block
	 * 
	 * @param buffer
	 *            - global (!) array of bytes, containing block
	 * @param offset
	 *            - offset in array
	 * @param sector
	 *            - number of sector to write to
	 * @param block
	 *            - number of block to write to
	 */
	public void setBlock(byte buffer[], short offset, byte sector, byte block);

	/**
	 * SIO method to read block. If client is eligible to perform this
	 * operation, this method will copy BLOCK_LENGTH bytes from internal image
	 * at specified sector and block to buffer starting from offset
	 * 
	 * @param buffer
	 *            - global (!) array of bytes, containing block
	 * @param offset
	 *            - offset in array
	 * @param sector
	 *            - number of sector to read from
	 * @param block
	 *            - number of block to read from
	 */
	public void getBlock(byte buffer[], short offset, byte sector, byte block);
}
