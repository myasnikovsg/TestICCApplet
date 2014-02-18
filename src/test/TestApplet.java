package test;

/**
 * @author Hedin
 * Applet for ICC, complying to ISO / IEC 7816:2005 and GlobalPlatfrom Specification 2.2.1
 * Operations: 
 * 1) Activate (load memory image of MiFare Classic XK, where X is generic symbol)
 * 2) Deactivate (save memory image, acquired during last activation and supposedly changed by 
 * 		other applets)
 * 3) Change keys of sectors
 * 4) Unlock applet.
 * Implements Shareable, no check to acquire except for AID is performed.
 * Implements ExtendedLength, as 127 bytes is obviously not enough.  
 */

import org.globalplatform.CVM;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacardx.apdu.ExtendedLength;

public class TestApplet extends Applet implements ExtendedLength,
		MiFareIOInterface {

	private CVM mCVM;
	private SecureChannel mSecureChannel;
	private short offset;
	private byte processed;
	private byte sector;
	private byte block;
	private short bytesLeft;

	// Proprietary INS constants
	final static byte INS_ACTIVATE = (byte) 0x01;
	final static byte INS_DEACTIVATE = (byte) 0x02;
	final static byte INS_SET_KEYS = (byte) 0x03;
	final static byte INS_UNLOCK = (byte) 0x04;
	final static byte INS_PERSONALIZE = (byte) 0x05;
	final static byte INS_GET_STATE = (byte) 0x06;
	final static byte INS_GET_MIFARE_STATE = (byte) 0x07;
	final static byte INS_GET_VERSION = (byte) 0x08;
	final static byte INS_GET_TRIES_REMAINING = (byte) 0x09;
	final static byte INS_VERIFY_PIN = (byte) 0x0A;

	// proprietary State constants
	final static byte STATE_INSTALLED = (byte) 0x07;
	final static byte STATE_PERSONALIZED = (byte) 0x0F;
	final static byte STATE_PIN_LOCKED = (byte) 0x17;

	// proprietary MiFare State constants
	final static byte MIFARE_STATE_ACTIVE = (byte) 0x01;
	final static byte MIFARE_STATE_INACTIVE = (byte) 0x02;

	// version number, 0xXY, there X - major version, Y - minor version
	final static byte APP_VERSION = (byte) 0x10;

	// image of MiFare memory
	MiFareImage image;

	// Privilege related constants
	final static byte CVM_MANAGMENT_PRIVILEGE_MASK = (byte) 0x04;

	// Trusted AIDs
	final static AID TRUSTED_AID_1 = new AID(new byte[] { 0x00, 0x01, 0x02,
			0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
			0x0E, 0x0F }, (byte) 0x00, (byte) 0x10);

	// Error codes
	final static short SW_CVM_MANAGMENT_NOT_ALLOWED = (short) 0x6301;
	final static short SW_MIFARE_SAK_NOT_SUPPORTED = (short) 0x6302;
	final static short SW_PIN_VERIFICATION_REQUIRED = (short) 0x6303;
	final static short SW_PIN_INVALID = (short) 0x6304;
	final static short SW_OUT_OF_COMMIT_MEMORY = (short) 0x6305;
	final static short SW_CLIENT_UNAUTHORISED = (short) 0x6306;
	final static short SW_MIFARE_VERSION_NOT_SUPPORTED = (short) 0x6307;

	/**
	 * Applet constructor. To intstaniate applet we pass parameters of install
	 * method.
	 * 
	 * @param buffer
	 * @param offset
	 * @param length
	 */
	private TestApplet(byte[] buffer, short offset, byte length) {
		// First byte, according to GP, codes length of AID for current instance
		byte AID_Length = (byte) buffer[offset];
		byte AID_Offset = (byte) (offset + 1); // 1
		// This byte codes privileges length
		byte privileges_Length = (byte) buffer[(short) (AID_Offset + AID_Length)];
		byte privileges_Offset = (byte) (AID_Offset + AID_Length + 1); // 3
		// This byte codes length of PIN, 1 byte skipped is Proprietary Data
		// length, useless in this context
		byte PIN_Length = (byte) buffer[(short) (privileges_Offset
				+ privileges_Length + 1)];
		byte PIN_Offset = (byte) (privileges_Offset + privileges_Length + 1 + 1); // 6
		byte PINCount_Offset = (byte) (PIN_Offset + PIN_Length + 1);
		// This byte codes length of SAK
		byte SAK_Offset = (byte) (PINCount_Offset + 1);
		// First byte of privileges, according to GP, contains CVM Management
		// Privilege
		byte appletPrivileges = (byte) buffer[(short) (offset + 1 + AID_Length + 1)];
		// Check if CVM Management Privilege granted
		if ((appletPrivileges & CVM_MANAGMENT_PRIVILEGE_MASK) == 0)
			ISOException.throwIt(SW_CVM_MANAGMENT_NOT_ALLOWED);
		// Get CVM Object
		mCVM = GPSystem.getCVM(GPSystem.CVM_GLOBAL_PIN);
		// Set PIN
		mCVM.update(buffer, PIN_Offset, PIN_Length, CVM.FORMAT_HEX);
		// Set try limit
		mCVM.setTryLimit((byte) buffer[PINCount_Offset]);
		// create image of memory according to supplied SAK
		image = MiFareImage.getInstance(buffer[SAK_Offset]);
		// null returned if mifare type not recognized
		if (image == null)
			ISOException.throwIt(SW_MIFARE_VERSION_NOT_SUPPORTED);
		// during registration, cardContentState is set to
		// GPSYstem.STATE_SELECTABLE
		register(buffer, AID_Offset, AID_Length);
		// explicitly set cardContentState to STATE_INSTALLED
		GPSystem.setCardContentState(STATE_INSTALLED);
	}

	/**
	 * Install method, as specified in GP, buffer contains
	 * 	- AID
	 *  - Application Privileges
	 *  - Application Proprietary Data (LV notation).
	 *    Latter consists of:
	 *     - PIN length (1 byte)
	 *     - PIN value (1 - 8 byte), HEX notation
	 *     - PIN retry count (1 byte)
	 *     - SAK value (1 byte)
	 *     
	 * @param bArray
	 * @param bOffset
	 * @param bLength
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new TestApplet(bArray, bOffset, bLength);
	}

	public void process(APDU apdu) throws ISOException {
		// In case we're dealing with select command
		if (selectingApplet())
			return;
		byte[] buffer = apdu.getBuffer();
		// don't know what to do with CLA: all bits are used (logigcal channel,
		// secure messaging, chaining). So, this applet accept ANY CLA.
		/*
		 * Eliminating bits 1-4 (logical channel ) byte cla = (byte)
		 * (buffer[ISO7816.OFFSET_CLA] & (byte) SM_MASK); // Check whether we
		 * support this CLA if (cla != CLA_PROPRIETARY)
		 * ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		 */
		// Commands dispatching to appropriate methods. Each method checks
		// secure messaging if needed.
		byte ins = buffer[ISO7816.OFFSET_INS];
		switch (ins) {
		case INS_ACTIVATE:
			activate(apdu);
			break;
		case INS_DEACTIVATE:
			deactivate(apdu);
			break;
		case INS_SET_KEYS:
			setKeys(apdu);
			break;
		case INS_UNLOCK:
			unlock(apdu);
			break;
		case INS_PERSONALIZE:
			personalize(apdu);
			break;
		case INS_GET_STATE:
			getState(apdu);
			break;
		case INS_GET_MIFARE_STATE:
			getMifareState(apdu);
			break;
		case INS_GET_VERSION:
			getVersion(apdu);
			break;
		case INS_GET_TRIES_REMAINING:
			getTriesRemaining(apdu);
			break;
		case INS_VERIFY_PIN:
			verifyPIN(apdu);
			break;
		default:
			processSCCommand(apdu);
			break;
		}
	}

	public boolean select() {
		// Get Secure Channel instance
		mSecureChannel = GPSystem.getSecureChannel();
		return true;
	}

	public void deselect() {
		// Reset channel security to avoid data leaks
		mSecureChannel.resetSecurity();
	}

	/**
	 * Method to handle activate command.
	 * Applet shall be personalized and unlocked,
	 * miFare image shall be inactive to answer this command. 
	 * 
	 * @param apdu
	 * 
	 */
	private void activate(APDU apdu) {
		checkState(STATE_PERSONALIZED);
		// Already active
		if (image.isActive())
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if (!mCVM.isVerified())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		readData(apdu);
		image.setActive(true);
	}

	/**
	 * Subroutine to read the image of memory from apdu.
	 * Used by activate(..) and personalize(..).
	 * Checks for state handled by respective methods.
	 * Transaction initiated at the start of method and committed in the end.
	 * Assumes that JCRE aborting transaction on uncaught exception.
	 * 
	 * @param apdu
	 *            - buffer (starting with CDATA offset) consists of list of
	 *            sectors, encoded as
	 *             - Number of sector (1 byte) 
	 *             - Number of block of sector (1 byte)
	 *             - Block 0 (BLOCK_LENGTH bytes)
	 *             - Block 1 (BLOCK_LENGTH bytes) 
	 *             - ...
	 *             - Block N (BLOCK_LENGTH bytes), where N is class specific
	 */
	private void readData(APDU apdu) {
		// Rough check to determine if we can process command as transaction
		if (image.getCapacity() > JCSystem.getUnusedCommitCapacity())
			ISOException.throwIt(SW_OUT_OF_COMMIT_MEMORY);
		JCSystem.beginTransaction();
		apdu.setIncomingAndReceive();
		// Check whether we perform personalization right now
		if (GPSystem.getCardContentState() == STATE_INSTALLED)
			if (apdu.isSecureMessagingCLA())
				processSecureMessage(apdu);
			else
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		bytesLeft = apdu.getIncomingLength();
		readPortion(apdu);
		readSectorNumber(apdu);
		// Assumption for sake of time - blocks always come in full,
		// otherwise ISO7816.SW_DATA_INVALID is thrown.
		while (true) {
			readBlock(apdu);
			// If current block is not the last in sector, next byte should be
			// number of next block.
			if (!image.isTrailerBlock(sector, block))
				readBlockNumber(apdu);
			else {
				// Next byte is number of sector, followed by number of block,
				// or the end of data reached. It's the only way to leave while
				// clause without exception thrown.
				if (bytesLeft == 0)
					break;
				readSectorNumber(apdu);
			}
		}
		JCSystem.commitTransaction();
	}

	/**
	 * Subroutine to read number of sector from apdu. 
	 * If data ended after this operation,
	 *  an attempt to read next portion is done.
	 * 
	 * @param apdu
	 */
	private void readSectorNumber(APDU apdu) {
		// Read sector, move offset
		sector = apdu.getBuffer()[offset++];
		processed++;
		// Is sector valid
		image.checkBlock(sector, (byte) 0);
		// Try to load next portion
		if (apdu.getIncomingLength() == processed && !readPortion(apdu))
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		// If STATE_INSTALLED, we're in personalization command now,
		// set supplied sector as available.
		if (GPSystem.getCardContentState() == STATE_INSTALLED)
			image.setSectorPersonalized(sector);
		else // Otherwise, we need to check is supplied sector was available
				// during personalization.
		if (image.isSectorPersonalized(sector))
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		// Sector number always followed by block number
		readBlockNumber(apdu);
	}

	/**
	 * Subroutine to read number of block for apdu.
	 * If data ended after this operation,
	 * an attempt to read next portion is done.
	 * 
	 * @param apdu
	 */
	private void readBlockNumber(APDU apdu) {
		// Read block number, move offset.
		block = apdu.getBuffer()[offset++];
		processed++;
		// Is block valid for current sector.
		image.checkBlock(sector, block);
		// Try to load next portion
		if (apdu.getIncomingLength() == processed && !readPortion(apdu))
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	}

	/**
	 * Subroutine to read a block from apdu.
	 * If data ended after this operation and current block
	 * is not the last in its sector, an attempt to read next
	 * portion is done.
	 * 
	 * @param apdu
	 */
	private void readBlock(APDU apdu) {
		// Block shall be supplied as full
		if (apdu.getIncomingLength() - processed < MiFareImage.BLOCK_LENGTH)
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		// Read block, move offset
		image.setBlock(apdu.getBuffer(), offset, sector, block);
		processed += MiFareImage.BLOCK_LENGTH;
		offset += MiFareImage.BLOCK_LENGTH;
		// Reached end of portion, block is not the last in section, data ended
		if (apdu.getIncomingLength() == processed
				&& !image.isTrailerBlock(sector, block) && !readPortion(apdu))
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	}

	/**
	 * Subroutine to get next portion of data.
	 * This method can be invoked during conversation via 
	 * Secure Channel, so unwrapping/decrypting is done if
	 * necessary.
	 * 
	 * @param apdu
	 * @return true if attempt to load next portion was successful, false
	 *         otherwise
	 */
	private boolean readPortion(APDU apdu) {
		// How much left
		bytesLeft -= apdu.getIncomingLength();
		if (bytesLeft == 0)
			return false;
		// Receiving portion of data
		apdu.receiveBytes(apdu.getOffsetCdata());
		// Check whether we perform personalization right now.
		// This code is direct copy/paste of fragment in readData(..)
		// unfortunately, there is no setIncoming(..) method in APDU.
		if (GPSystem.getCardContentState() == STATE_INSTALLED)
			if (apdu.isSecureMessagingCLA())
				processSecureMessage(apdu);
			else
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		// Reseting offset
		offset = apdu.getOffsetCdata();
		// Reseting processed
		processed = 0;
		return true;
	}

	/**
	 * Method to handle deactivate command.
	 * Applet shall be personalized and unlocked, 
	 * miFare image shall be active to answer this command.
	 * Export message constructed if following manner:
	 *  - Number of sector 0 (1 byte) 
	 *  - Number of block 0 in sector 0 (1 byte) 
	 *  - Block 0 in sector 0 (BLOCK_LENGTH bytes) 
	 *  - Number of block 1 in sector 0 (1 byte) 
	 *  - Block 1 in sector 0 (BLOCK_LENGTH bytes) 
	 *  - ... 
	 *  - Number of sector 1 (1 byte) 
	 *  -
	 *  ...
	 * 
	 * @param apdu
	 */
	private void deactivate(APDU apdu) {
		checkState(STATE_PERSONALIZED);
		// already deactivated
		if (!image.isActive())
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		// Transmit now
		apdu.setOutgoing();
		// Calculating length of answer
		apdu.setOutgoingLength(image.getExportLength());
		// for each personalized sector
		for (byte sector = 0x00; sector < image.getSectorsNumber(); sector++)
			if (image.isSectorPersonalized(sector)) // sector can be exported
													// only if personalized
				exportSector(apdu);
		// deactivate image
		image.setActive(false);
	}

	/**
	 * Subroutine to export sector.
	 * Format is a follows:
	 *  - Sector number (1 byte) 
	 *  - Block 0 number (1 byte)
	 *  - Block 0 (BLOCK_LENGTH bytes) 
	 *  - ... 
	 *  - Block N (BLOCK_LENGTH bytes)
	 * 
	 * @param apdu
	 * @param sector
	 *            - sector to export
	 */
	private void exportSector(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// sending sector number
		buffer[ISO7816.OFFSET_CDATA] = sector;
		apdu.sendBytes(ISO7816.OFFSET_CDATA, (short) 0x0001);
		// for each block in sector
		for (block = 0x00; block < image.getBlocksNumber(sector); block++) {
			// put block number
			buffer[ISO7816.OFFSET_CDATA] = block;
			// copy block in buffer
			image.getBlock(buffer, (short) (ISO7816.OFFSET_CDATA + 0x01),
					sector, block);
			// send block number and block
			apdu.sendBytes(ISO7816.OFFSET_CDATA,
					(short) (MiFareImage.BLOCK_LENGTH + 0x01));
		}
	}

	/**
	 * Method to handle set key command.
	 * Applet shall be personalized and unlocked to answer this command.
	 * Applet Data field of apdu contains
	 *  - Number of sector (1 byte)
	 *  - Type of key (1 byte) (see MiFareImage class)
	 *  - Key (5 byte).
	 * As the only change in persistent memory is key copy, we
	 * assume that atomic arrayCopy will do the trick and not initiating
	 * transaction.
	 * 
	 * @param apdu
	 */
	private void setKeys(APDU apdu) {
		checkState(STATE_PERSONALIZED);
		// Can't set keys while in active state
		if (image.isActive())
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		apdu.setIncomingAndReceive();
		// must be secured
		if (!apdu.isSecureMessagingCLA())
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		// Secured
		processSecureMessage(apdu);
		// buffer contains unwrapped and decrypted data
		byte buffer[] = apdu.getBuffer();
		// Data field should contain number of sector (1 byte), type of key (1
		// byte)
		// and key itself (KEY_LENGTH)
		if (apdu.getIncomingLength() < (byte) (MiFareImage.KEY_LENGTH + 0x02))
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		offset = apdu.getOffsetCdata();
		// Setting key
		image.setKey(buffer, (short) (offset + 0x02), buffer[offset],
				buffer[(byte) (offset + 0x01)]);
	}

	/**
	 * Method to handle unlock command.
	 * Sets state of applet to STATE_PERSONALIZED and reset
	 * PIN to supplied.
	 * Retry Limit is not subject to change.
	 * In any state other than STATE_PIN_LOCKED,
	 * ISO7816.SW_CONDITIONS_NOT_SATISFIED is thrown.
	 * apdu buffer contains new PIN.
	 * 
	 * @param apdu
	 */
	private void unlock(APDU apdu) {
		checkState(STATE_PIN_LOCKED);
		apdu.setIncomingAndReceive();
		// must be secured
		if (!apdu.isSecureMessagingCLA())
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		// Secured
		processSecureMessage(apdu);
		// updating PIN. mCVM transitions to ACTIVE state
		mCVM.update(apdu.getBuffer(), apdu.getOffsetCdata(),
				(byte) apdu.getIncomingLength(), CVM.FORMAT_HEX);
		// Applet transitions to PERSONALIZED state
		GPSystem.setCardContentState(STATE_PERSONALIZED);
	}

	/**
	 * Method to handle personalize command.
	 * Applet shall be installed to process this.
	 * 
	 * @param apdu
	 */
	private void personalize(APDU apdu) {
		checkState(STATE_INSTALLED);
		readData(apdu);
		image.setActive(true);
	}

	/**
	 * Method to handle getState command.
	 * Applet should not be personalized or unlocked
	 * to answer this command.
	 * 
	 * @param apdu
	 */
	private void getState(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		buffer[ISO7816.OFFSET_EXT_CDATA] = GPSystem.getCardContentState();
		apdu.setOutgoingAndSend((short) ISO7816.OFFSET_EXT_CDATA, (short) 0x01);
	}

	/**
	 * Method to handle getMifareState command.
	 * Applet shall be personalized and unlocked to answer
	 * this command.
	 * 
	 * @param apdu
	 */
	private void getMifareState(APDU apdu) {
		checkState(STATE_PERSONALIZED);
		byte buffer[] = apdu.getBuffer();
		buffer[ISO7816.OFFSET_EXT_CDATA] = (image.isActive()) ? MIFARE_STATE_ACTIVE
				: MIFARE_STATE_INACTIVE;
		apdu.setOutgoingAndSend((short) ISO7816.OFFSET_EXT_CDATA, (short) 0x01);
	}

	/**
	 * Method to handle getVersion command.
	 *  Applet should not be personalized or unlocked
	 *  to answer this command.
	 * 
	 * @param apdu
	 */
	private void getVersion(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		buffer[ISO7816.OFFSET_EXT_CDATA] = (byte) APP_VERSION;
		apdu.setOutgoingAndSend((short) ISO7816.OFFSET_EXT_CDATA, (short) 0x01);
	}

	/**
	 * Method to handle getTriesReamining command.
	 * Applet shall be personalized and unlocked to answer
	 * this command.
	 * It will NOT answer with '0x00' in case applet is pin-blocked.
	 * 
	 * @param apdu
	 */
	private void getTriesRemaining(APDU apdu) {
		checkState(STATE_PERSONALIZED);
		byte[] buffer = apdu.getBuffer();
		buffer[ISO7816.OFFSET_EXT_CDATA] = mCVM.getTriesRemaining();
		apdu.setOutgoingAndSend((short) ISO7816.OFFSET_EXT_CDATA, (short) 0x01);
	}

	/**
	 * Method to handle verifyPIN command.
	 * Applet shall be personalized and unlocked to answer this command.
	 * Usually submitted after SW_PIN_VERIFICATION_REQUIRED response.
	 * 
	 * @param apdu
	 */
	private void verifyPIN(APDU apdu) {
		checkState(STATE_PERSONALIZED);
		// verify PIN
		apdu.setIncomingAndReceive();
		if (mCVM.verify(apdu.getBuffer(), apdu.getOffsetCdata(),
				(byte) apdu.getIncomingLength(), CVM.FORMAT_HEX) == CVM.CVM_FAILURE) {
			// If PIN was not verified, and try limit was reached, transition to
			// PIN_LOCKED state
			if (mCVM.isBlocked())
				GPSystem.setCardContentState(STATE_PIN_LOCKED);
			// In any case, answer with PIN_INVALID status word
			ISOException.throwIt(SW_PIN_INVALID);
		}
		// if verify(..) succeeds, SW 0x9000 appended automatically
	}

// ------------------------------------------ Internal check methods ----------------------------------

	/**
	 * Since many handle methods is only callable when applet is in
	 * STATE_PERSONALIZED, this dedicated method was introduced.
	 * If applet is in supplied state, nothing happens. Otherwise
	 * ISO7816.SW_CONDITIONS_NOT_SATISFIED is thrown.
	 * 
	 * @param state
	 *            - state to check against
	 */
	private void checkState(byte state) {
		if (GPSystem.getCardContentState() != state)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	}

	/**
	 * Method to check if client with a given AID is eligible to perform
	 * read-write operations
	 * 
	 * @param client
	 *            - AID of client
	 */
	private void checkConditionsToInteroperate(AID client) {
		if (!client.equals(TRUSTED_AID_1))
			ISOException.throwIt(SW_CLIENT_UNAUTHORISED);
		if (image.isActive())
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	}

// ------------------------------------------- Secure Messaging methods -----------------------------

	/**
	 * This method is called in case INS of APDU was not recognized.
	 * This MAY mean that this command have something to do with
	 * Secure Channel Protocol.
	 * As defined in GlobalPlatform Specification, applet passing
	 * all unrecognized commands to this method.
	 * 
	 * @param apdu
	 */
	private void processSCCommand(APDU apdu) {
		// apdu is processed by SecureChannel instance. All errors occurring
		// during this process
		// are for Secure Domain to handle. Applet is only required to pass
		// answer, if any.
		byte responseLength = (byte) mSecureChannel.processSecurity(apdu);
		if (responseLength != 0)
			apdu.setOutgoingAndSend((short) ISO7816.OFFSET_EXT_CDATA,
					responseLength);
	}
	/**
	 * Method to unwrap and decrypt message.  
	 * @param apdu
	 */
	private void processSecureMessage(APDU apdu) {
		// unwrapping message, if no secure messaging specified in CLA of apdu,
		// nothing is done.
		mSecureChannel.unwrap(apdu.getBuffer(), apdu.getOffsetCdata(),
				apdu.getIncomingLength());
		// decrypting
		mSecureChannel.decryptData(apdu.getBuffer(), apdu.getOffsetCdata(),
				apdu.getIncomingLength());
	}

// -------------------------------------------SIO methods---------------------------------------------

	public void setBlock(byte[] buffer, short offset, byte sector, byte block) {
		// Fetching and checking AID of client
		checkConditionsToInteroperate(JCSystem.getPreviousContextAID());
		image.checkAccess(sector, block);
		image.setBlock(buffer, offset, sector, block);
	}

	public void getBlock(byte[] buffer, short offset, byte sector, byte block) {
		// Fetching and checking AID of client
		checkConditionsToInteroperate(JCSystem.getPreviousContextAID());
		image.checkAccess(sector, block);
		image.getBlock(buffer, offset, sector, block);
	}

}
