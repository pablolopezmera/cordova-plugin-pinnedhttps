package me.lockate.plugins;

import java.io.BufferedReader;
import java.io.IOException;

/*
* To be fair, this has been harvested from : http://www.tutorialspoint.com/compile_java_online.php?PID=0Bw_CjBb95KQMMl9BbUpjU1lmOG8
*/

public class LineReader {
	private BufferedReader br;

	public LineReader(BufferedReader _br){
		br = _br;
	}

	public String readExactLine() throws IOException{
		StringBuilder sb = new StringBuilder();
		boolean testNewLine = false;
		int i; //Current char code

		while ((i = br.read()) >= 0){
			sb.append((char)i);

			if (i == '\n') break;

			if (testNewLine){ //If this code is reached and exectued, that means it \r wasn't followed by \n. Return current string
				sb.setLength(sb.length() - 1); //Truncate the last char
				br.reset(); //Go one char back
				break; //Effectively returning the current line
			}

			if (i == '\r'){
				br.mark(1);
				testNewLine = true; //Prepare to see if the \r is followed by \n
			}
		}

		return sb.length() == 0 ? null : sb.toString();
	}

}
