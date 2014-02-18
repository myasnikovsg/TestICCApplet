package test;
/**
 * @author Hedin
 * Abstract class, encapsulating common behavior
 * of MiFare Classic XK, there X is generic symbol.
 * Concrete realizations provide calculate methods. 
 */
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public abstract class MiFareImage {
	// length of a block, for both 1K and 4K
	protected static final byte BLOCK_LENGTH = 0x10;

	// length of keys A and B
	protected static final byte KEY_LENGTH = 0x05;

	// offset from the start of trailer to key B
	protected static final byte KEY_B_OFFSET = 0xA;

	// constants of key types
	public static final byte KEY_A_TYPE = 0x01;
	public static final byte KEY_B_TYPE = 0x02;

	// SAKs of supported MiFare
	final static byte MIFARE_1K_SAK = (byte) 0x08;
	final static byte MIFARE_4K_SAK = (byte) 0x18;

	// Byte array, representing image of MiFare memory
	protected byte image[];

	// Byte array, representing availability of sectors. Coded on bitmap, i.e.
	// sector k is available
	// if (bit_sectors[k / 8] & (1 << (k % 8))) == 1
	protected byte bit_sectors[];

	// Current state of miFare memory
	private boolean active = false;

	/**
	 * Method to calculate offset of a given sector's trailer, containing key A
	 * (5 byte), Access bits (3 bytes + 1 user data byte), key B (5 byte)
	 * 
	 * @param sector
	 *            - number of sector to calculate for
	 * @return offset in image, representing first byte of trailer
	 * @throws ISOException
	 */
	protected abstract short getTrailerOffset(byte sector);

	/**
	 * Method to calculate offset of block
	 * 
	 * @param sector
	 *            - number of sector to calculate for
	 * @param block
	 *            - number of block to calculate for
	 * @return offset in image, representing first byte of block
	 * @throws ISOException
	 */
	protected abstract short getBlockOffset(byte sector, byte block);

	/**
	 * Method to check violation of boundaries. In case of violation
	 * ISO7816.SW_DATA_INVALID is thrown.
	 * 
	 * @param sector
	 *            - number of sector to check.
	 * @param block
	 *            - number of block to check. Pass 0 to check only for sector.
	 * @throws ISOException
	 */
	protected abstract void checkBlock(byte sector, byte block);

	/**
	 * Method to check whether block is last in given section
	 * 
	 * @param sector
	 *            - number of sector to check.
	 * @param block
	 *            - number of block to check.
	 * @return true if supplied block is last in it's section, false otherwise.
	 * @throws ISOException
	 */
	protected abstract boolean isTrailerBlock(byte sector, byte block);

	/**
	 * Returns capacity of concrete MiFare card's memory.
	 * 
	 * @return capacity of concrete MiFare card's memory.
	 */
	public abstract short getCapacity();

	/**
	 * Returns length of export message
	 * 
	 * @return length of export message
	 */
	protected abstract short getExportLength();

	/**
	 * Returns number of blocks in specified sector
	 * 
	 * @param sector
	 *            - sector to calculate for
	 * @return number of sectors
	 */
	public abstract byte getBlocksNumber(byte sector);

	/**
	 * Factory method for instaniating.
	 * 
	 * @param SAK
	 *            - SAK of needed image.
	 * @return instance of image, null if not recognized.
	 */
	public static MiFareImage getInstance(byte SAK) {
		switch (SAK) {
		case MIFARE_1K_SAK:
			return new MiFareImage1K();
		case MIFARE_4K_SAK:
			return new MiFareImage4K();
		default:
			return null;
		}
	}

	/**
	 * Method to set key of sector.
	 * 
	 * @param buffer
	 *            - byte array containing key.
	 * @param offset
	 *            - offset of key in buffer
	 * @param sector
	 *            - sector number, counting from 0.
	 * @param type
	 *            - type of key, static const
	 * @throws
	 */
	protected void setKey(byte buffer[], short offset, byte sector, byte type) {
		Util.arrayCopy(buffer, offset, image,
				(short) ((type == KEY_A_TYPE) ? getTrailerOffset(sector)
						: getTrailerOffset(sector) + KEY_B_OFFSET), KEY_LENGTH);
	}

	/**
	 * Method to retrieve a block from miFare memory image. Said block copied to
	 * buffer at offset.
	 * 
	 * @param buffer
	 *            - byte array to store block. It shall be global.
	 * @param offset
	 *            - offset at which to store block in buffer
	 * @param sector
	 *            - number of sector from which to get block.
	 * @param block
	 *            - number of block
	 * @throws ISOException
	 */
	public void getBlock(byte buffer[], short offset, byte sector, byte block) {
		Util.arrayCopy(image, getBlockOffset(sector, block), buffer, offset,
				BLOCK_LENGTH);
	}

	/**
	 * Method to store a block in miFare memory image. Said block copied in
	 * image from buffer
	 * 
	 * @param buffer
	 *            - byte array containing block. It shall be global.
	 * @param offset
	 *            - offset of said block.
	 * @param sector
	 *            - number of sector of block to set.
	 * @param block
	 *            - number of block to set.
	 */
	public void setBlock(byte buffer[], short offset, byte sector, byte block) {
		Util.arrayCopy(buffer, offset, image, getBlockOffset(sector, block),
				BLOCK_LENGTH);
	}

	/**
	 * Returns number of sectors of image
	 * 
	 * @return number of sectors
	 */
	public byte getSectorsNumber() {
		return (byte) (bit_sectors.length * 0x08);
	}

	/**
	 * Method to check if sector was specified as available during
	 * personalization
	 * 
	 * @param sector
	 *            - number of sector to check
	 * @return true if available, false otherwise
	 */
	protected boolean isSectorPersonalized(byte sector) {
		checkBlock(sector, (byte) 0);
		return (bit_sectors[sector / 8] & ((byte) (1 << (sector % 8)))) == 0x01;
	}

	/**
	 * Method to personalize sector. Only personalized sectors are eligible to
	 * write and read by another applets.
	 * 
	 * @param sector
	 *            - number of sector to set personalized
	 */
	public void setSectorPersonalized(byte sector) {
		checkBlock(sector, (byte) 0);
		bit_sectors[sector / 8] |= (byte) (1 << (sector % 8));
	}

	/**
	 * Sets concrete image object active or inactive.
	 * 
	 * @param flag
	 */
	public void setActive(boolean flag) {
		active = flag;
	}

	/**
	 * Checks whether concrete image object active.
	 * 
	 * @return
	 */
	public boolean isActive() {
		return active;
	}

	/**
	 * Method to check right to access block
	 * 
	 * @param sector
	 *            - number of sector to check for
	 * @param block
	 *            - number of block to check for
	 */
	public void checkAccess(byte sector, byte block) {
		// Check boundaries
		checkBlock(sector, block);
		// {sector:0, block:0) - issuer info, last block - trailer: not eligible
		// to read/write.
		if ((sector == ((byte) 0x00) && block == ((byte) 0x00))
				|| isTrailerBlock(sector, block))
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	}
}
