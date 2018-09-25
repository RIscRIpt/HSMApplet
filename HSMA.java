package HSMApplet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class HSMA extends Applet {
    private static final byte CLA = 0x48;
    
    private static final byte INS_PIN = 0x01;
    private static final byte INS_IV = (byte)0x14;
    private static final byte INS_KEY_DES = (byte)0xCD;
    private static final byte INS_KEY_AES = (byte)0xCA;

    private static final byte INS_INIT = (byte)0x17;
    private static final byte INS_UPDATE = (byte)0xAE;
    private static final byte INS_DOFINAL = (byte)0xDF;

    private static final byte P1_ENCRYPT = Cipher.MODE_ENCRYPT; // 0x02
    private static final byte P1_DECRYPT = Cipher.MODE_DECRYPT; // 0x01

    private static final byte P2_DES_ECB = (byte)0xDE;
    private static final byte P2_DES_CBC = (byte)0xDC;
    private static final byte P2_AES_ECB = (byte)0xAE;
    private static final byte P2_AES_CBC = (byte)0xAC;

    private static final short IV_MAX_LENGTH = 32;

    private static final byte[] PIN = { (byte)0xFF, (byte)0xFF };
    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte PIN_MAX_LENGTH = 8;

    private OwnerPIN pin;
    
    private short iv_length;
    private byte[] iv;

    private DESKey des_key;
    private AESKey aes_key;
    private final DESKey des1_key;
    private final DESKey des2_key;
    private final DESKey des3_key;
    private final AESKey aes128_key;
    private final AESKey aes192_key;
    private final AESKey aes256_key;
    
    private Cipher current_cipher;
    private Cipher aes_ecb_cipher;
    private Cipher aes_cbc_cipher;
    private final Cipher des_ecb_cipher;
    private final Cipher des_cbc_cipher;
    private final Cipher aes128_ecb_cipher;
    private final Cipher aes128_cbc_cipher;
    private final Cipher aes192_ecb_cipher;
    private final Cipher aes192_cbc_cipher;
    private final Cipher aes256_ecb_cipher;
    private final Cipher aes256_cbc_cipher;
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HSMA(bArray, bOffset, bLength);
    }
    
    protected HSMA(byte[] bArray, short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_MAX_LENGTH);
        pin.update(PIN, (short)0, (byte)PIN.length);
        
        des_ecb_cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
        des_cbc_cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        aes128_ecb_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        aes128_cbc_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aes192_ecb_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_192_ECB_NOPAD, false);
        aes192_cbc_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_192_CBC_NOPAD, false);
        aes256_ecb_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_256_ECB_NOPAD, false);
        aes256_cbc_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_256_CBC_NOPAD, false);
        
        iv = JCSystem.makeTransientByteArray(IV_MAX_LENGTH, JCSystem.CLEAR_ON_DESELECT);

        des1_key = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES, false);
        des2_key = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_2KEY, false);
        des3_key = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_3KEY, false);

        aes128_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
        aes192_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_192, false);
        aes256_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);

        register();
    }

    private void init() {
        iv_length = 0;

        des_key = null;
        aes_key = null;

        current_cipher = null;
    }

    public boolean select() {
        init();
        return true;
    }

    public void deselect() {
        init();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        
        byte[] buffer = apdu.getBuffer();
        
        if (buffer[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        short length = apdu.setIncomingAndReceive();

        byte ins = buffer[ISO7816.OFFSET_INS];
        if (ins == INS_PIN) {
            check_pin(apdu, length);
            return;
        }
        
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        switch (ins) {
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
            case INS_IV:
                process_iv(apdu, length);
                break;
            case INS_KEY_DES:
                process_key_des(apdu, length);
                break;
            case INS_KEY_AES:
                process_key_aes(apdu, length);
                break;
            case INS_INIT:
                process_init(apdu, length);
                break;
            case INS_UPDATE:
                process_update(apdu, length);
                break;
            case INS_DOFINAL:
                process_dofinal(apdu, length);
                break;
        }
    }
    
    private void check_pin(APDU apdu, short length) {
        boolean result = pin.check(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (byte)length);
        if (!result) {
            byte triesRemaining = pin.getTriesRemaining();
            ISOException.throwIt((short)(0x62C0 | triesRemaining));
        }
    }
    
    private void process_iv(APDU apdu, short length) {
        byte[] buffer = apdu.getBuffer();
        iv_length = length;
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, iv, (short)0, iv_length);
    }

    private void process_key_des(APDU apdu, short length) {
        byte[] buffer = apdu.getBuffer();
        switch (length) {
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                break;
            case 8:
                des_key = des1_key;
                break;
            case 16:
                des_key = des2_key;
                break;
            case 24:
                des_key = des3_key;
                break;
        }
        des_key.setKey(buffer, ISO7816.OFFSET_CDATA);
    }

    private void process_key_aes(APDU apdu, short length) {
        byte[] buffer = apdu.getBuffer();
        switch (length) {
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                break;
            case 16:
                aes_key = aes128_key;
                aes_ecb_cipher = aes128_ecb_cipher;
                aes_cbc_cipher = aes128_cbc_cipher;
                break;
            case 24:
                aes_key = aes192_key;
                aes_ecb_cipher = aes192_ecb_cipher;
                aes_cbc_cipher = aes192_cbc_cipher;
                break;
            case 32:
                aes_key = aes256_key;
                aes_ecb_cipher = aes256_ecb_cipher;
                aes_cbc_cipher = aes256_cbc_cipher;
                break;
        }
        aes_key.setKey(buffer, ISO7816.OFFSET_CDATA);
    }

    private void process_init(APDU apdu, short length) {
        byte[] buffer = apdu.getBuffer();
        
        byte mode = buffer[ISO7816.OFFSET_P1];
        switch (mode) {
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
            case P1_DECRYPT:
            case P1_ENCRYPT:
                break;
        }
        
        switch (buffer[ISO7816.OFFSET_P2]) {
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
            case P2_DES_ECB:
                current_cipher = des_ecb_cipher;
                current_cipher.init(des_key, mode);
                break;
            case P2_DES_CBC:
                current_cipher = des_cbc_cipher;
                current_cipher.init(des_key, mode, iv, (short)0, (short)iv_length);
                break;
            case P2_AES_ECB:
                current_cipher = aes_ecb_cipher;
                current_cipher.init(aes_key, mode);
                break;
            case P2_AES_CBC:
                current_cipher = aes_cbc_cipher;
                current_cipher.init(aes_key, mode, iv, (short)0, (short)iv_length);
                break;
        }

        if (length > 0) {
            process_dofinal(apdu, length);
        }
    }

    private void process_update(APDU apdu, short length) {
        if (current_cipher == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        length = current_cipher.update(buffer, ISO7816.OFFSET_CDATA, length, buffer, (short)0);
        apdu.setOutgoingAndSend((short)0, length);
    }

    private void process_dofinal(APDU apdu, short length) {
        if (current_cipher == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        length = current_cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, length, buffer, (short)0);
        apdu.setOutgoingAndSend((short)0, length);
    }

}
