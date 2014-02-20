package test;

/**
 * @author Hedin 
 * Concrete class extending abstract MiFareImage.
 * This class implements entity "MiFare 1K Memory".
 * Total capacity is 1024 byte
 * Memory of 1K organized in 16 sectors of 4 blocks, 
 * with each block comprised of 16 bytes. 
 */
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class MiFareImage1K extends MiFareImage {

	private static final short CAPACITY = 0x400;
	private static final byte SECTOR_LENGTH = 0x40;
	private static final byte SECTOR_NUMBER = (byte) (CAPACITY / SECTOR_LENGTH);
	private static final byte BLOCK_LENGTH = 0x10;
	private static final byte BLOCK_NUMBER = (byte) (SECTOR_LENGTH / BLOCK_LENGTH);

	public MiFareImage1K() {
		image = new byte[CAPACITY];
		bit_sectors = new byte[(short) (SECTOR_NUMBER / ((byte) 0x08))];
		password = new byte[(short) (SECTOR_NUMBER * PASSWORD_LENGTH)];
	}

	protected short getBlockOffset(byte sector, byte block) {
		checkBlock(sector, block);
		return (short) (SECTOR_LENGTH * sector + BLOCK_LENGTH * block);
	}

	protected short getTrailerOffset(byte sector) {
		return getBlockOffset(sector, (byte) (BLOCK_NUMBER - 0x01));
	}

	protected void checkBlock(byte sector, byte block) {
		if (sector >= SECTOR_NUMBER)
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		if (block >= BLOCK_NUMBER)
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	}

	protected boolean isTrailerBlock(byte sector, byte block)
			throws ISOException {
		checkBlock(sector, block);
		return block == (byte) (BLOCK_NUMBER - 0x01);
	}

	protected short getExportLength() {
		short count = 0x000;
		// for each personalized sector
		for (byte sector = 0x00; sector < getSectorsNumber(); sector++)
			if (isSectorPersonalized(sector))
				// add to count number of blocks in sector + (1 byte) of sector
				// number
				count += (BLOCK_NUMBER + 0x0001);
		return count;
	}

	public byte getBlocksNumber(byte sector) {
		return BLOCK_NUMBER;
	}

}
