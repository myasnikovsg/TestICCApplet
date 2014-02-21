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
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public abstract class MiFareImage {
	// length of a block, for both 1K and 4K
	protected static final byte BLOCK_LENGTH = 0x10;

	// length of keys A and B
	protected static final byte KEY_LENGTH = 0x06;

	// offset from the start of trailer to key B
	protected static final byte KEY_B_OFFSET = 0xA;

	// length of password for miFare sector
	public static final byte PASSWORD_LENGTH = 0x08;

	// constants of key types
	public static final byte KEY_A_TYPE = 0x01;
	public static final byte KEY_B_TYPE = 0x02;

	// SAKs of supported MiFare
	final static byte MIFARE_1K_SAK = (byte) 0x08;
	final static byte MIFARE_4K_SAK = (byte) 0x18;

	// storage for 16-byte key for 3DES-EDE
	private byte DKey[] = new byte[0x10];
	
	// blank (0x00) 8 byte of data to encrypt during password calculation
	private byte blankData[] = new byte[0x08];
	
	// DES-KEY
	DESKey dKey;
	
	// DES-Cipher
	Cipher cipher;
	
	// counter
	private byte i;
	
	// temp for swap
	private byte temp;

	// Byte array, representing image of MiFare memory
	protected byte image[];

	// Byte array, representing availability of sectors. Coded on bitmap, i.e.
	// sector k is available
	// if (bit_sectors[k / 8] & (1 << (k % 8))) == 1
	protected byte bit_sectors[];

	// Byte array containing password for miFare sector. Each 8 byte aligned
	// block reperesnt auth token.
	protected byte password[];

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
	 * Returns capacity required for personalization of concrete MiFare card's
	 * memory.
	 * 
	 * @return capacity required for personalization of concrete MiFare card's
	 *         memory.
	 */
	public short getPersonalizationCapacity() {
		// each sector requires trailer block + 8 bytes of password
		return (short) (getSectorsNumber() * (BLOCK_LENGTH + 0x08));
	}

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
	public void getBlock(byte buffer[], short offset, byte sector, byte block,
			byte b_offset, byte b_length) {
		if (b_offset >= BLOCK_LENGTH || BLOCK_LENGTH - b_length >= b_offset)
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		Util.arrayCopy(image,
				(short) (getBlockOffset(sector, block) + b_offset), buffer,
				offset, b_length);
	}

	public byte[] getImage() {
		return image;
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
	public void setBlock(byte buffer[], short offset, byte sector, byte block,
			byte b_offset, byte b_length) {
		if (b_offset >= BLOCK_LENGTH || BLOCK_LENGTH - b_length >= b_offset)
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		Util.arrayCopy(buffer, offset, image,
				(short) (getBlockOffset(sector, block) + b_offset), b_length);
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

	/**
	 * Method to calculate password for a given sector.
	 * Password = invert(3DES-EDE(D_KEY_A, D_KEY_B, {0x00:8}))(8 byte).
	 * 3DES-EDE = DES((DES^-1(DES(DATA, E)), D), E), where E = D_KEY_A, D = D_KEY_B.
	 * {0x00:8} = {0x00, 0x00, ...} - 8 bytes.
	 * Let KEY (MIFARE secret key, A or B) be as follows (6 bytes):
	 * {K5_7, K5_6, K5_5, ..., K5_0}, {K4_7, ...,K4_0}, ..., {K0_7, ..., K0_0}.
	 * Kx_y denotes y-th bit of x-th byte.
	 * D_KEY_A = 8 bytes.
	 * bytes 0-5(i) = {Ki_6, Ki_5, ..., Ki_0, 0}.
	 * byte 6 = {0, K0_7, K1_7, ..., K5_7, 0}.
	 * byte 7 = {0, 0, ..., 0}.
	 * D_KEY_B mirrored copy, same algo.
	 * All keys are given in already inverted notation.
	 * 
	 * @param sector
	 *            - number of sector to calculate for
	 */
	protected void calculatePassword(byte sector) {
		// null our key
		for (i = 0x00; i < PASSWORD_LENGTH * 2; i++)
			DKey[i] = 0x00;
		// DKey = 16 bytes : {inverted(DKeyA)(8 bytes), inverted(DKeyB)(8
		// bytes)}
		for (i = 0x00; i < 0x06; i++) {
			DKey[i] = (byte) (image[(short) (getTrailerOffset(sector) + i)] << 1);
			DKey[PASSWORD_LENGTH + i + 2] = (byte) (image[(short) (getTrailerOffset(sector)
					+ KEY_B_OFFSET + i)] << 1);
		}
		for (i = 0x00; i < 0x06; i++) {
			DKey[0x06] |= ((image[(short) (getTrailerOffset(sector) + i)] >> 0x07) << (0x06 - i));
			DKey[PASSWORD_LENGTH + 0x01] |= ((image[(short) (getTrailerOffset(sector)
					+ KEY_B_OFFSET + (0x05 - i))] >> 0x07) << (0x06 - i));
		}
		// inverting keys in DKey
		for (i = 0x00; i < PASSWORD_LENGTH / 2; i++) {
			temp = DKey[i];
			DKey[i] = DKey[PASSWORD_LENGTH - i - 0x01];
			DKey[PASSWORD_LENGTH - i - 1] = temp;
			temp = DKey[PASSWORD_LENGTH + i];
			DKey[PASSWORD_LENGTH + i] = DKey[PASSWORD_LENGTH * 0x02 - i - 0x01];
			DKey[PASSWORD_LENGTH * 0x02 - i - 0x01] = temp;
		}
		// building key
		dKey = (DESKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_DES_TRANSIENT_DESELECT,
				KeyBuilder.LENGTH_DES3_2KEY, false);
		// setting precalculated value
		dKey.setKey(DKey, (short) 0x00);
		// obtaining cipher instance
		cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		// initializing instance
		cipher.init(dKey, Cipher.MODE_ENCRYPT);
		// blanking area of encryption
		for (i = 0x00; i < PASSWORD_LENGTH; i++)
			blankData[i] = 0x00;
		// encrypting
		cipher.doFinal(blankData, (short) 0x00, PASSWORD_LENGTH, password,
				getPasswordOffset(sector));
		// now password at appropriate offset contain inverted password for
		// sector
		// invert it
		for (i = 0x00; i < PASSWORD_LENGTH / 2; i++) {
			temp = password[getPasswordOffset(sector) + i];
			password[getPasswordOffset(sector) + i] = password[getPasswordOffset(sector)
					+ PASSWORD_LENGTH - i - 1];
			password[getPasswordOffset(sector) + PASSWORD_LENGTH - i - 1] = temp;
		}
		// password calculated and stored
	}

	/**
	 * Method to be used after loading of initial data during personalization.
	 * This method will calculate passwords for each personalized sector, using
	 * keys A and B as supplied before.
	 */
	public void init() {
		// for each personalized sector
		for (byte sector = 0x00; sector < getSectorsNumber(); sector++)
			if (isSectorPersonalized(sector))
				calculatePassword(sector);
	}

	/**
	 * Returns offset in password array representing start of password for
	 * sector.
	 * 
	 * @param sector
	 *            - number of sector to calculate for
	 * @return offset in password array representing start of password for
	 *         sector.
	 */
	public short getPasswordOffset(byte sector) {
		return (short) (sector * PASSWORD_LENGTH);
	}

	/**
	 * Getter for password array.
	 * 
	 * @return password array.
	 */
	public byte[] getPassword() {
		return password;
	}
}
