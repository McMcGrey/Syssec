package at.syssec.ss15.ss.ab3;


/**
 * Interface für die Verwendung des RSA-Kryptosystems.
 * 
 * @author Raphael Wigoutschnigg
 */
public interface PasswordTools {

	/**
	 * Erzeugt einen Salted-Hash
	 * 
	 * @param password
	 *            Das Passwort
	 * @return SaltedHash-Objekt
	 */
	public SaltedHash createSaltedHash(String password);

	/**
	 * Prüft, ob ein Passwort zum übergebenen Salted-Hash passt
	 * 
	 * @param password
	 *            Das Passwort
	 * @param hash
	 *            Der Salted-Hash
	 * @return ob das Passwort zum Salted-Hash passt
	 */
	public boolean checkSaltedHash(String password, SaltedHash hash);

	/**
	 * Bestimmt einen Key mithilfe der PBKDF2-Funktion. Sind Parameter null, so
	 * sind diese nicht zu verwenden. Verwenden Sie als PRF (pseudo random
	 * function) eine Hashfunktion (vgl. Klasse MessageDigest)
	 * 
	 * @param password
	 *            Das Passwort
	 * @param salt
	 *            Der Salt
	 * @param iterations
	 *            Anzahl an Iterationen
	 * @param dkLen
	 *            Länge des erzeugten Schlüsseln (derived key length)
	 * @return den erzeugten Schlüssel
	 */
	public byte[] PBKDF2(byte[] password, byte[] salt, int iterations, int dkLen);

	/**
	 * Hilfsklasse zur Speicherung eines Salted-Hashes
	 * 
	 * @author Raphael Wigoutschnigg
	 */
	public class SaltedHash {

		public SaltedHash() {

		}

		public SaltedHash(byte[] hash, byte[] salt) {
			super();
			this.hash = hash;
			this.salt = salt;
		}

		private byte[] hash;
		private byte[] salt;

		public byte[] getHash() {
			return hash;
		}

		public void setHash(byte[] hash) {
			this.hash = hash;
		}

		public byte[] getSalt() {
			return salt;
		}

		public void setSalt(byte[] salt) {
			this.salt = salt;
		}

	}
}