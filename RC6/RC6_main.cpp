#include <iostream>
#include <fstream>
#include <cstring>
#include <algorithm>

#include "RC6.hpp"

#define RC6_W 32
#define RC6_R 20

/******************************************************************
 * Function: usage
 * Input: <int> argc, <char **> argv
 * Output: void
 * Description: Prints out how to run the RC6 program. 
 *              Is called if program input is incorrect
 ******************************************************************/
void usage(int argc, char *argv[]){
  std::cout << "User Input:" << std::endl;
  for(int i = 0; i < argc; ++i){
    std::cout << argv[i] << " ";
  }
  std::cout << std::endl;

  // Print out usage
  std::cout << std::endl;
  std::cout << "usage: \n./run ./input.txt ./output.txt" << std::endl;
}

/******************************************************************
 * Function: parseRC6Textfile
 * Input: <std::fstream> file, <std::string> &mode, 
 *          <std::string> &text, <std::string> &userkey
 * Output: bool
 * Description: Parse textfile to be used for RC6 excryption and
 *              decryption. Extracts mode of RC6, text to encrypt
 *              or decrypt, and userkey
 ******************************************************************/
bool parseRC6Textfile(std::istream& file, std::string& mode,
		   std::string& text, std::string& userkey){
  std::string line;
  int linenum = 0;
  bool err = false;
  if(file){
    while(!file.eof() && !err){
      getline(file, line);
      switch(linenum){
      case 0:
	if(line=="Encryption" ||
	   line=="Decryption"){
	  mode = line;
	}else{
	  throw std::runtime_error("Line 0 is \"" + line + "\"");
	  err = true;
	}
	++linenum;
	break;
      case 1:
	if(line.compare(0, strlen("plaintext: "), "plaintext: ") == 0){
	  text = line.substr(strlen("plaintext: "), line.length() - strlen("plaintext: "));
	}else if(line.compare(0, strlen("ciphertext: "), "ciphertext: ") == 0){
	  text = line.substr(strlen("ciphertext: "), line.length() - strlen("ciphertext: "));
	}else{
	  throw std::runtime_error("Line 1 is \"" + line + "\"");
	  err = true;
	}
	++linenum;
	break;
      case 2:
	if(line.compare(0, strlen("userkey: "), "userkey: ") == 0){
	  userkey = line.substr(strlen("userkey: "), line.length() - strlen("userkey: "));
	}else{
	  err = true;
	}
	++linenum;
	break;
      default:
	break;
      }
    }
  }

  return err;
}

/******************************************************************
 * Function: keyLength
 * Input: <std::string> key
 * Output: unsigned int
 * Description: Determines b for the RC6-w/r/b cryptography.
 *              It outputs the length of the encryption key in bytes
 ******************************************************************/
void remove_whitespace(std::string &str){
  str.erase(std::remove_if(str.begin(), str.end(), isspace), str.end());
}

/******************************************************************
 * Function: keyLength
 * Input: <std::string> key
 * Output: unsigned int
 * Description: Determines b for the RC6-w/r/b cryptography.
 *              It outputs the length of the encryption key in bytes
 ******************************************************************/
unsigned int keylength(std::string key){
  return key.length() / 2;
}

/******************************************************************
 * Function: main
 * Input: <int> argc, <char **> argv
 * Output: int
 * Description: ./run ./input.txt ./output.txt 
 *              Runs RC6 program to encrypt the message in 
 *              given to the program. The input.txt contains
 *              the user key and the plaintext or ciphertext.
 *              If plaintext, then an encryption is performed.
 *              If ciphertext, then a decryption is performed.
 *              The output of the program is either the ciphertext 
 *              (for encryption) or the plaintext (for decryption).
 ******************************************************************/
int main(int argc, char *argv[]){

  if(argc != 3){
    std::cout << "Incorrect number of arguments" << std::endl;
    usage(argc, argv);
    return 0;
  }
  
  std::ifstream inputfile(argv[1], std::ios::binary);
  if(!inputfile.is_open()){
    std::cerr << "Unable to open input file" << std::endl;
    return 1;
  }
  
  std::ofstream outputfile(argv[2], std::ios::binary);
  if(!outputfile.is_open()){
    std::cerr << "Unable to open output file" << std::endl;
    return 2;
  }

  std::string mode, text, userkey;

  if(parseRC6Textfile(inputfile, mode, text, userkey) != 0){
    std::cerr << "Error parsing input file" << std::endl;
    return 3;
  }

  remove_whitespace(text);
  remove_whitespace(userkey);

  RC6 rc6 = RC6(RC6_W, RC6_R, keylength(userkey));
  const std::string result = rc6.run(mode, text, userkey);

  if(mode=="Encryption"){
    outputfile << "ciphertext: " << result << std::endl;
  }else if(mode=="Decryption"){
    outputfile << "plaintext: " << result << std::endl;
  }

  inputfile.close();
  outputfile.close();

  return 0;
}
