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

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacardx.apdu.ExtendedLength;
import javacardx.external.Memory;
import javacardx.external.MemoryAccess;

public class TestApplet extends Applet implements ExtendedLength,
		MiFareIOInterface {

	private OwnerPIN mPIN;
	private SecureChannel mSecureChannel;
	private MemoryAccess miFareAccess;
	private short offset;
	private byte processed;
	private byte sector;
	private byte block;
	private short bytesLeft;
	private byte state;

	// Proprietary INS constants
	final static byte INS_ACTIVATE = (byte) 0x01;
	final static byte INS_DEACTIVATE = (byte) 0x02;
	final static byte INS_SET_KEYS = (byte) 0x03;
	final static byte INS_UNLOCK = (byte) 0x04;
	final static byte INS_PERSONALIZE = (byte) 0x05;
	final static byte INS_GET_STATUS = (byte) 0x06;
	final static byte INS_VERIFY_PIN = (byte) 0x07;

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
	private TestApplet(byte[] buffer, short PIN_offset, byte PIN_length,
			byte PINTryLimit, byte SAK) {
		mPIN = new OwnerPIN(PINTryLimit, PIN_length);
		// Set PIN
		mPIN.update(buffer, PIN_offset, PIN_length);
		// create image of memory according to supplied SAK
		image = MiFareImage.getInstance(SAK);
		// null returned if mifare type not recognized
		if (image == null)
			ISOException.throwIt(SW_MIFARE_VERSION_NOT_SUPPORTED);
		miFareAccess = Memory.getMemoryAccessInstance(
				Memory.MEMORY_TYPE_MIFARE, null, (short) 0x00);
		state = STATE_INSTALLED;
	}

	/**
	 * Install method, as specified in GP, buffer contains - AID - Application
	 * Privileges - Application Proprietary Data (LV notation). Latter consists
	 * of: - PIN length (1 byte) - PIN value (1 - 8 byte), HEX notation - PIN
	 * try limit (1 byte) - SAK value (1 byte)
	 * 
	 * @param bArray
	 * @param bOffset
	 * @param bLength
	 */
	public static void install(byte bArray[], short bOffset, byte bLength) {
		short AID_offset = (short) (bOffset + 0x01);
		byte AID_length = bArray[bOffset];
		short privileges_offset = (short) (AID_offset + AID_length + 0x01);
		byte privileges_length = bArray[privileges_offset - 0x01];
		short PIN_offset = (short) (privileges_offset + privileges_length + 0x01);
		byte PIN_length = bArray[PIN_offset - 0x01];
		byte PINTryLimit = bArray[PIN_offset + PIN_length];
		byte SAK = bArray[PIN_offset + PIN_length + 0x01];
		new TestApplet(bArray, PIN_offset, PIN_length, PINTryLimit, SAK)
				.register(bArray, AID_offset, AID_length);
	}

	public void process(APDU apdu) throws ISOException {
		// In case we're dealing with select command
		if (selectingApplet())
			return;
		// Commands dispatching to appropriate methods. Each method checks
		// secure messaging if needed.
		switch (apdu.getBuffer()[ISO7816.OFFSET_INS]) {
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
		case INS_GET_STATUS:
			getStatus(apdu);
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
	 * Method to handle activate command. Applet shall be personalized and
	 * unlocked, miFare image shall be inactive to answer this command.
	 * 
	 * @param apdu
	 * 
	 */
	private void activate(APDU apdu) {
		checkState(STATE_PERSONALIZED);
		// Already active
		if (image.isActive())
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if (!mPIN.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		// for each personalized sector
		for (byte sector = 0x00; sector < image.getSectorsNumber(); sector++)
			if (image.isSectorPersonalized(sector))
				for (block = 0x00; block < (image.getBlocksNumber(sector) - 0x01); block++) {
					// (sector 0: block 0) and (sector k : trailer block) cannot
					// be read.
					if (sector == 0x00 && block == 0x00)
						continue;
					miFareAccess.readData(image.getImage(),
							image.getBlockOffset(sector, block),
							image.getPassword(),
							image.getPasswordOffset(sector),
							MiFareImage.PASSWORD_LENGTH, sector, block,
							MiFareImage.BLOCK_LENGTH);
				}
		image.setActive(true);
	}

	/**
	 * Method to handle deactivate command. Applet shall be personalized and
	 * unlocked, miFare image shall be active to answer this command.
	 * 
	 * @param apdu
	 */
	private void deactivate(APDU apdu) {
		checkState(STATE_PERSONALIZED);
		// already deactivated
		if (!image.isActive())
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if (!mPIN.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		// Transmit now
		apdu.setOutgoing();
		// Calculating length of answer
		apdu.setOutgoingLength(image.getExportLength());
		// for each personalized sector
		for (sector = 0x00; sector < image.getSectorsNumber(); sector++)
			if (image.isSectorPersonalized(sector)) { // sector can be exported
														// only if personalized
				for (block = 0x00; block < image.getBlocksNumber(sector); block++)
					// (sector 0: block 0) cannot be written.
					if (sector == 0x00 && block == 0x00)
						continue;
					else
						miFareAccess.writeData(image.getImage(),
								image.getBlockOffset(sector, block),
								MiFareImage.BLOCK_LENGTH, image.getPassword(),
								image.getPasswordOffset(sector),
								MiFareImage.PASSWORD_LENGTH, sector, block);
				// as we just wrote sector, it's keys may be altered. To access
				// it next time, we need to recalculate password for sector
				image.calculatePassword(sector);
			}
		// deactivate image
		image.setActive(false);
	}

	/**
	 * Method to handle set key command. Applet shall be personalized and
	 * unlocked to answer this command. Applet Data field of apdu contains -
	 * Number of sector (1 byte) - Type of key (1 byte) (see MiFareImage class)
	 * - Key (5 byte). As the only change in persistent memory is key copy, we
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
	 * Method to handle unlock command. Sets state of applet to
	 * STATE_PERSONALIZED and reset PIN to supplied. Retry Limit is not subject
	 * to change. In any state other than STATE_PIN_LOCKED,
	 * ISO7816.SW_CONDITIONS_NOT_SATISFIED is thrown. apdu buffer contains new
	 * PIN.
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
		// updating PIN. mPIN transitions to ACTIVE state
		mPIN.update(apdu.getBuffer(), apdu.getOffsetCdata(),
				(byte) apdu.getIncomingLength());
		// Applet transitions to PERSONALIZED state
		state = STATE_PERSONALIZED;
	}

	/**
	 * Method to handle personalize command. Applet shall be installed to
	 * process this.
	 * 
	 * @param apdu
	 */
	private void personalize(APDU apdu) {
		checkState(STATE_INSTALLED);
		// Rough check to determine if we can process command as transaction
		if (image.getPersonalizationCapacity() > JCSystem
				.getUnusedCommitCapacity())
			ISOException.throwIt(SW_OUT_OF_COMMIT_MEMORY);
		// start transaction
		JCSystem.beginTransaction();
		// security check inside
		readPortion(apdu, true);
		// Assumption for sake of time - blocks always come in full with sector
		// number
		while (readSectorTrailer(apdu))
			;
		image.init();
		state = STATE_PERSONALIZED;
		JCSystem.commitTransaction();
	}

	/**
	 * Subroutine to read sector trailer during personalization. Data formatted
	 * as follows: - Sector number (1 byte) - Trailer block (BLOCK_LENGTH bytes)
	 * If data ended after this operation, an attempt to read next portion is
	 * done.
	 * 
	 * @param apdu
	 * @return true if next trailer is available, false otherwise
	 */
	private boolean readSectorTrailer(APDU apdu) {
		// Check whether buffer contains necessary data
		if (apdu.getIncomingLength() - processed < MiFareImage.BLOCK_LENGTH + 0x01)
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		// Read sector number, move offset
		sector = apdu.getBuffer()[offset++];
		processed++;
		// Is sector valid
		image.checkBlock(sector, (byte) 0);
		// Read trailer
		image.setBlock(apdu.getBuffer(), offset, sector,
				(byte) (image.getBlocksNumber(sector) - 0x01), (byte) 0,
				MiFareImage.BLOCK_LENGTH);
		processed += MiFareImage.BLOCK_LENGTH;
		// Mark sector as personalized
		image.setSectorPersonalized(sector);
		// Try to load next portion
		if (apdu.getIncomingLength() == processed && !readPortion(apdu, false))
			return false;
		return true;
	}

	/**
	 * Subroutine to get next portion of data. This method can be invoked during
	 * conversation via Secure Channel, so unwrapping/decrypting is done.
	 * 
	 * @param apdu
	 * @return true if attempt to load next portion was successful, false
	 *         otherwise
	 */
	private boolean readPortion(APDU apdu, boolean isFirstPortion) {
		// How much left
		bytesLeft -= apdu.getIncomingLength();
		if (bytesLeft == 0)
			return false;
		// Receiving portion of data
		// If it is first portion, we should first set incoming
		if (isFirstPortion)
			apdu.setIncomingAndReceive();
		else
			// otherwise, just receive bytes
			apdu.receiveBytes(apdu.getOffsetCdata());
		// should be secured
		processSecureMessage(apdu);
		// Reseting offset
		offset = apdu.getOffsetCdata();
		// Reseting processed
		processed = 0;
		return true;
	}

	/**
	 * Method to handle getStatus command. Applet should not be personalized or
	 * unlocked to answer this command.
	 * 
	 * @param apdu
	 */
	private void getStatus(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		offset = apdu.getOffsetCdata();
		// putting state
		buffer[offset++] = state;
		// putting mifare state
		buffer[offset++] = (image.isActive()) ? MIFARE_STATE_ACTIVE
				: MIFARE_STATE_INACTIVE;
		// putting version
		buffer[offset++] = APP_VERSION;
		// putting try count remaining
		buffer[offset] = mPIN.getTriesRemaining();
		// transmitting
		apdu.setOutgoingAndSend(apdu.getOffsetCdata(), (short) 0x04);
	}

	/**
	 * Method to handle verifyPIN command. Applet shall be personalized and
	 * unlocked to answer this command. Usually submitted after
	 * SW_PIN_VERIFICATION_REQUIRED response.
	 * 
	 * @param apdu
	 */
	private void verifyPIN(APDU apdu) {
		checkState(STATE_PERSONALIZED);
		// verify PIN
		apdu.setIncomingAndReceive();
		if (mPIN.check(apdu.getBuffer(), apdu.getOffsetCdata(),
				(byte) apdu.getIncomingLength())) {
			// If PIN was not verified, and try limit was reached, transition to
			// PIN_LOCKED state
			if (mPIN.getTriesRemaining() == 0x00)
				state = STATE_PIN_LOCKED;
			// In any case, answer with PIN_INVALID status word
			ISOException.throwIt(SW_PIN_INVALID);
		}
		// if verify(..) succeeds, SW 0x9000 appended automatically
	}

// ------------------------------------------ Internal check methods ----------------------------------

	/**
	 * Since many handle methods is only callable when applet is in
	 * STATE_PERSONALIZED, this dedicated method was introduced. If applet is in
	 * supplied state, nothing happens. Otherwise
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
	 * This method is called in case INS of APDU was not recognized. This MAY
	 * mean that this command have something to do with Secure Channel Protocol.
	 * As defined in GlobalPlatform Specification, applet passing all
	 * unrecognized commands to this method.
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
	 * Method to unwrap secure message content.
	 * 
	 * @param apdu
	 */
	private void processSecureMessage(APDU apdu) {
		// unwrapping message, if no secure messaging specified in CLA of apdu,
		// exception is thrown
		if (!apdu.isSecureMessagingCLA())
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		mSecureChannel.unwrap(apdu.getBuffer(), apdu.getOffsetCdata(),
				apdu.getIncomingLength());
	}

// ------------------------------------------- SIO methods ---------------------------------------------

	public void setBlock(byte[] buffer, short offset, byte sector, byte block,
			byte b_offset, byte b_length) {
		// Fetching and checking AID of client
		checkConditionsToInteroperate(JCSystem.getPreviousContextAID());
		image.checkAccess(sector, block);
		image.setBlock(buffer, offset, sector, block, b_offset, b_length);
	}

	public void getBlock(byte[] buffer, short offset, byte sector, byte block,
			byte b_offset, byte b_length) {
		// Fetching and checking AID of client
		checkConditionsToInteroperate(JCSystem.getPreviousContextAID());
		image.checkAccess(sector, block);
		image.getBlock(buffer, offset, sector, block, b_offset, b_length);
	}

}
