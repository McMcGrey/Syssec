package at.syssec.ss15.ss.ab1.impl.Kohlbacher_Wutti;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import at.syssec.ss15.ss.ab1.RSA;

public class RSAImpl implements RSA {
	private BigInteger fermat[] = new BigInteger[] {
			new BigInteger( "3" ),
			new BigInteger( "5" ),
			new BigInteger( "17" ),
			new BigInteger( "257" ),
			new BigInteger( "65537" ),
	};

	@Override
	public BigInteger generatePrime( int n ) {
		/** Die Wahrscheinlichkeit, dass probablePrime() eine Zahl zurückliefert die keine Primzahl ist liegt bei unter 2^-100.
		 * für 100% Primzahlen müsste ein effizienter Primzahltest durchgeführt werden.
		 *
		 * Da System.currentTimeMillis als Seed für Random verwendet wird, wird vor der Erzeugung der Zahl kurz gewartet. Ansonst kommt es unter Umständen zu dem Fall, dass
		 * p = q
		 */
		try {
			Thread.sleep( 1 );
		} catch ( InterruptedException e ) {
			e.printStackTrace();
		}
		return BigInteger.probablePrime( n, new Random( System.currentTimeMillis() ) );
	}

	@Override
	public BigInteger generateEncryptionExponent( BigInteger p, BigInteger q ) {
		//Euler phi-function
		BigInteger phi = p.subtract( BigInteger.ONE ).multiply( q.subtract( BigInteger.ONE ) );
		//public exponent
		//prefer fermat numbers
		BigInteger e = findFermatExponent( phi );
		// if fermat numbers not valid for phi( n )
		if ( e.equals( BigInteger.ZERO ) ) {
			//create random exponent
			do {
				//Create prime number with half the bitLength of phi(n)
				e = BigInteger.probablePrime( ( int ) ( phi.bitLength() * 0.5 ), new Random( System.currentTimeMillis() ) );
			} while ( phi.mod( e ).compareTo( BigInteger.ZERO ) == 0 );
		}
		return e;
	}

	@Override
	public BigInteger generateDecryptionExponent( BigInteger p, BigInteger q,
												 BigInteger e ) {
		return e.modInverse( p.subtract( BigInteger.ONE ).multiply( q.subtract( BigInteger.ONE ) ) );
	}

	@Override
	public byte[] encrypt( byte[] message, BigInteger n, BigInteger e ) {
		BigInteger messageInteger = new BigInteger( message );
		if ( messageInteger.bitLength() < n.bitLength() ) {
			return messageInteger.modPow( e, n ).toByteArray();
		} else {
			int keySize = n.bitLength();                       // In bits
			int clearTextSize = Math.min( ( keySize-1 ) / 8, 256);   // In bytes
			int cipherTextSize = 1 + ( keySize-1 ) / 8;            // In bytes
			ByteBuffer inputBuffer = ByteBuffer.wrap( message );
			List< byte[] > outputList = new ArrayList< byte[] >();
			byte[] clearTextBlock = new byte[ clearTextSize ];
			byte[] cipherTextBlock = new byte[ cipherTextSize ];
			long blocks = 0;

			inputBuffer.get( clearTextBlock );
			int dataSize = clearTextBlock.length;
			boolean isPadded = false;

			while ( dataSize > 0 ) {
				blocks++;
				if ( dataSize < clearTextSize ) {
					padBytesBlock( clearTextBlock, dataSize );
					isPadded = true;
				}

				BigInteger clearText = new BigInteger( 1, clearTextBlock );
				BigInteger cipherText = clearText.modPow( e, n );
				byte[] cipherTextData = cipherText.toByteArray();
				putBytesBlock( cipherTextBlock, cipherTextData );
				outputList.add( cipherTextBlock );
				cipherTextBlock = new byte[ cipherTextSize ];

				try {
					inputBuffer.get(clearTextBlock);
					dataSize = clearTextBlock.length;
				}catch (Exception exep) {
					clearTextBlock = new byte[inputBuffer.limit() - inputBuffer.position()];
					inputBuffer.get(clearTextBlock);
					dataSize = clearTextBlock.length;
				}
			}

			if ( !isPadded && clearTextBlock.length != 0 ) {
				blocks++;
				padBytesBlock( clearTextBlock, 0 );
				BigInteger clearText = new BigInteger( 1, clearTextBlock );
				BigInteger cipherText = clearText.modPow( e, n);
				byte[] cipherTextData = cipherText.toByteArray();
				putBytesBlock( cipherTextBlock, cipherTextData );
				outputList.add( cipherTextBlock );
			}

			ByteBuffer outputBuffer = ByteBuffer.allocate( outputList.size() * outputList.get(0).length );

			for( byte[] b : outputList ) {
				outputBuffer.put( b );
			}

			return outputBuffer.array();
		}
	}

	@Override
	public byte[] decrypt( byte[] cipher, BigInteger n, BigInteger d ) {
		BigInteger cipherInteger = new BigInteger( cipher );
		if( cipherInteger.bitLength() <= n.bitLength() ) {
			byte[] result = cipherInteger.modPow( d, n ).toByteArray();
			return result;
		} else {
			int keySize = n.bitLength();                       // In bits
			int clearTextSize = Math.min( ( keySize - 1 ) / 8, 256 );   // In bytes
			int cipherTextSize = 1 + ( keySize - 1 ) / 8;            // In bytes

			ByteBuffer inputBuffer = ByteBuffer.wrap( cipher );
			List< byte[] > outputList = new ArrayList< byte[] >();
			byte[] clearTextBlock = new byte[ clearTextSize ];
			byte[] cipherTextBlock = new byte[ cipherTextSize ];
			long blocks = 0;
			int dataSize = 0;

			inputBuffer.get( cipherTextBlock );
			int blockSize = cipherTextBlock.length;
			while ( blockSize > 0 ) {
				blocks++;
				BigInteger cipherText = new BigInteger( 1, cipherTextBlock );
				BigInteger clearText = cipherText.modPow( d, n );
				byte[] clearTextData = clearText.toByteArray();
				putBytesBlock( clearTextBlock, clearTextData );

				dataSize = clearTextSize;
				if ( inputBuffer.limit() - inputBuffer.position() == 0 ) {
					dataSize = getDataSize( clearTextBlock );
					blockSize = 0;

					outputList.add( clearTextData );
				}
				if ( dataSize > 0 ) {
					outputList.add( clearTextBlock );
				}
				clearTextBlock = new byte[ clearTextSize ];
				if( blockSize > 0 ) {
					if( inputBuffer.limit() - inputBuffer.position() < cipherTextBlock.length ) {
						cipherTextBlock = new byte[ inputBuffer.limit() - inputBuffer.position() ];
						inputBuffer.get( cipherTextBlock );
						blockSize = cipherTextBlock.length;
					} else {
						inputBuffer.get( cipherTextBlock );
						blockSize = cipherTextBlock.length;
					}
				}
			}
			/**
			 * Herausfinden wie lange das Array wird, das zurückgegeben wird
			 */
			int resultArraySize = 0;
			for ( byte[] b : outputList ) {
				resultArraySize += b.length;
			}

			ByteBuffer outputBuffer = ByteBuffer.allocate( resultArraySize );
			for( byte[] b : outputList ) {
				outputBuffer.put( b );
			}
			return outputBuffer.array();
		}
	}

	/**
	 *
	 * @param phi Produkt der eulerschen Phi-Funktion (p-1)*(q-1)
	 * @return Fermatzahl zwischen [F1,F4] welche kleiner phi ist.
	 */
	private BigInteger findFermatExponent( BigInteger phi ) {
		for ( int i = fermat.length - 1 ; i >= 0 ; i-- ) {
			if( phi.compareTo( fermat[i] ) == 1 ) {
				if ( fermat[i].gcd( phi ).compareTo( BigInteger.ONE ) == 0 ) {
					return fermat[i];
				}
			}
		}
		return BigInteger.ZERO;
	}



	// Putting bytes data into a block
	public static void putBytesBlock( byte[] block, byte[] data ) {
		int bSize = block.length;
		int dSize = data.length;
		int i = 0;
		while ( i < dSize && i < bSize ) {
			block[bSize - i - 1] = data[dSize - i - 1];
			i++;
		}
		while ( i < bSize ) {
			block[bSize - i - 1] = (byte)0x00;
			i++;
		}
	}

	// Padding input message block
	public static void padBytesBlock( byte[] block, int dataSize ) {
		int bSize = block.length;
		int padSize = bSize - dataSize;
		int padValue = padSize%bSize;
		for ( int i = 0 ; i < padSize ; i++ ) {
			block[bSize - i - 1] = (byte) padValue;
		}
	}

	// Getting data size from a padded block
	public static int getDataSize( byte[] block ) {
		int bSize = block.length;
		int padValue = block[bSize - 1];
		return ( bSize - padValue ) % bSize;
	}

}
