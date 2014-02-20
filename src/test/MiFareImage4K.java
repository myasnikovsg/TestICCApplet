package test;

/**
 * @author Hedin 
 * Concrete class extending abstract MiFareImage.
 * This class implements entity "MiFare 4K Memory".
 * Total capacity is 4096 byte
 * Memory of 4K organized in 32 sectors of 4 blocks and 8 sectors of 16 blocks, 
 * with each block comprised of 16 bytes. 
 */
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class MiFareImage4K extends MiFareImage {

	private static final short CAPACITY = 0x1000;
	private static final byte LOWER_SECTOR_NUMBER = 0x20;
	private static final byte UPPER_SECTOR_NUMBER = 0x08;
	private static final byte BLOCK_LENGTH = 0x10;
	private static final byte LOWER_BLOCK_NUMBER = 0x04;
	private static final byte UPPER_BLOCK_NUMBER = 0x10;

	public MiFareImage4K() {
		image = new byte[CAPACITY];
		bit_sectors = new byte[(short) ((LOWER_SECTOR_NUMBER + UPPER_SECTOR_NUMBER) / ((byte) 0x08))];
		password = new byte[(short) (LOWER_SECTOR_NUMBER + UPPER_SECTOR_NUMBER)
				* PASSWORD_LENGTH];
	}

	protected short getTrailerOffset(byte sector) {
		// Pass number of last block in section to get offset of trailer
		return getBlockOffset(
				sector,
				(byte) ((sector < LOWER_SECTOR_NUMBER) ? (LOWER_BLOCK_NUMBER - 0x01)
						: (UPPER_BLOCK_NUMBER - 0x01)));
	}

	protected short getBlockOffset(byte sector, byte block) {
		checkBlock(sector, block);
		// In case we're dealing with lower sector block, calculate offset
		// sector and add offset
		// for block in sector.
		// Otherwise, calculate lower sectors's capacity, add offset for upper
		// sector and offset
		// for block in sector.
		// Since block length is independent of upper or lower, just multiply
		// by it.
		return (short) (((sector < LOWER_SECTOR_NUMBER) ? (sector
				* LOWER_BLOCK_NUMBER + block) : (LOWER_SECTOR_NUMBER
				* LOWER_BLOCK_NUMBER + (sector - LOWER_SECTOR_NUMBER - 1)
				* UPPER_BLOCK_NUMBER + block)) * BLOCK_LENGTH);
	}

	protected void checkBlock(byte sector, byte block) {
		// Check violation for sector
		if (sector >= UPPER_SECTOR_NUMBER + LOWER_SECTOR_NUMBER)
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		// Now sector have valid value. Check if block contained in lower sector
		if (sector < LOWER_SECTOR_NUMBER) {
			if (block >= LOWER_BLOCK_NUMBER)
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		} else // sector is an upper sector
		if (block >= UPPER_BLOCK_NUMBER)
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	}

	protected boolean isTrailerBlock(byte sector, byte block) {
		checkBlock(sector, block);
		return (sector < LOWER_BLOCK_NUMBER) ? (block == (byte) (LOWER_BLOCK_NUMBER - 0x01))
				: (block == (byte) (UPPER_BLOCK_NUMBER - 0x01));
	}

	protected short getExportLength() {
		short count = 0x0000;
		// for each personalized sector
		for (byte sector = 0x00; sector < getSectorsNumber(); sector++)
			if (isSectorPersonalized(sector))
				// add appropriate number of blocks + 1 byte of sector number
				count += ((sector < LOWER_SECTOR_NUMBER) ? LOWER_BLOCK_NUMBER
						: UPPER_BLOCK_NUMBER) + 0x0001;
		return count;
	}

	public byte getBlocksNumber(byte sector) {
		return (sector < LOWER_SECTOR_NUMBER) ? LOWER_BLOCK_NUMBER
				: UPPER_BLOCK_NUMBER;
	}

}
