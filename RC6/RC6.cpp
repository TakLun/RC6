#include "RC6.hpp"

RC6::RC6(unsigned int W, unsigned int R, unsigned int B){
  w = W;
  r = R;
  b = B;
  log_w = (unsigned int)log2(w);
  modulo = pow(2, w);
  S = new unsigned int[2 * r + 4];
}

void RC6::rc_constraints(const unsigned int &w, unsigned int &p, unsigned int &q){
  p = (unsigned int)std::ceil(((M_E - 2) * pow(2, w)));
  q = (unsigned int)((1.618033988749895 - 1) * pow(2, w));    // Golden Ratio
}

/******************************************************************
 * Function: left_rot
 * Input: <int> a, <unsigned int> b, <unsigned int> w
 * Output: int
 * Description: Rotate the w-bit word a to the left by the amount
 *              given by the least significant log w bits of b
 ******************************************************************/
int RC6::left_rot(unsigned int a, unsigned int b, unsigned int w){
  b <<= w - log_w;
  b >>= w - log_w;
  return (a << b) | (a >> (w - b));  
}

/******************************************************************
 * Function: right_rot
 * Input: <int> a, <unsigned int> b, <unsigned int> w
 * Output: int
 * Description: Rotate the w-bit word a to the right by the amount
 *              given by the least significant log w bits of b
 ******************************************************************/
int RC6::right_rot(unsigned int a, unsigned int b, unsigned int w){
  b <<= w - log_w;
  b >>= w - log_w;
  return (a >> b) | (a << (w - b));
}

/******************************************************************
 * Function: little_endian
 * Input: <std::string>
 * Output: std::string
 * Description: Convert input string to little endian version by bytes
 *              and return new little endian string. Assuming
 *              each character represents a byte
 ******************************************************************/
std::string RC6::little_endian(std::string str){
  std::string endian;
  
  if(str.length() % 2 == 0){
    for(std::string::reverse_iterator r_it = str.rbegin();
	r_it != str.rend();r_it = r_it + 2){
      endian.push_back(*(r_it+1));
      endian.push_back(*r_it);
    }
  }else{
    return str;
  }

  return endian;
}

/******************************************************************
 * Function: string_to_hex
 * Input: <std::string>
 * Output: std:string
 * Description: Converts input string to hex representation
 ******************************************************************/
std::string RC6::string_to_hex(std::string str){
  static const char* const hex_char = "0123456789ABCDEF";
  size_t len = str.length();
  
  std::string hex;
  for (size_t i = 0; i < len; ++i){
    const unsigned char c = str[i];
    hex.push_back(hex_char[c >> 4]);
    hex.push_back(hex_char[c & 15]);
  }
  return hex;
}

/******************************************************************
 * Function: hex_to_string 
 * Input: <std::string>
 * Output: std::string
 * Description: Converts input hex to string representation
 ******************************************************************/
std::string RC6::hex_to_string(std::string hex){
  static const char* const hex_char = "0123456789ABCDEF";
  size_t len = hex.length();

  std::string str;
  for (size_t i = 0; i < len; i += 2){
    char a = hex[i];
    const char* p = std::lower_bound(hex_char, hex_char + 16, a);
    
    char b = hex[i + 1];
    const char* q = std::lower_bound(hex_char, hex_char + 16, b);

    str.push_back(((p - hex_char) << 4) | (q - hex_char));
  }
  return str;
}

/******************************************************************
 * Function: key_schedule
 * Input: <std::string> key
 * Output: void
 * Description: Generates the key schedule for RC6. 
 *              The input takes the user-supplied b byte key preloaded
 *              in c-word L[0, ... , c-1]
 *              The function then outputs the w-bit round keys
 *              S[0, ... , 2r+3]
 ******************************************************************/
void RC6::key_schedule(std::string key){
  const unsigned int w_bytes = std::ceil((float)w / 8);
  const unsigned int c = std::ceil((float)b / w_bytes);

  unsigned int p, q;
  rc_constraints(w, p, q);

  std::cout << "magic constraints: \n";
  std::cout << "p: " << std::hex << p << "\nq: " << std::hex << q << "\n";
  std::cout << "actual: \np: 0xB7E15163\nq: 0x9E3779B9\n\n"; 

  L = new unsigned int[c];
  for(int i = 0; i < c; i++){
    L[i] = strtoul(little_endian(key.substr(w_bytes * 2 * i, w_bytes * 2)).c_str(), NULL, 16);
  }  

  S[0] = p;
  for(int i = 1; i <= (2 * r + 3); i++){
    S[i] = (S[i - 1] + q) % modulo;
  }

  unsigned int A = 0, B = 0, i = 0, j = 0;
  int v = 3 * std::max(c, (2 * r + 4));

  for(int s = 1; s <= v; s++){
    A = S[i] = left_rot((S[i] + A + B) % modulo, 3, w);
    B = L[j] = left_rot((L[j] + A + B) % modulo, (A + B), w);
    i = (i + 1) % (2 * r + 4);
    j = (j + 1) % c;
  }
}

/******************************************************************
 * Function: encrypt
 * Input: <const std::string>
 * Output: std::string
 * Description: Encrypt plaintext from the input string to ciphertext
 ******************************************************************/
std::string RC6::encrypt(const std::string &text){
  std::string result;
  
  unsigned int A, B, C, D;
  A = strtoul(text.substr(0, 8).c_str(), NULL, 16);
  B = strtoul(text.substr(8, 8).c_str(), NULL, 16);
  C = strtoul(text.substr(16, 8).c_str(), NULL, 16);
  D = strtoul(text.substr(24, 8).c_str(), NULL, 16);

  std::cout << "text: " << text << "\n";
  std::cout << "A: " << std::hex << A << "\n";
  std::cout << "B: " << std::hex << B << "\n";
  std::cout << "C: " << std::hex << C << "\n";
  std::cout << "D: " << std::hex << D << "\n\n";

  unsigned long int t, u, temp;

  B += S[0];
  D += S[1];
  for(int i = 1; i <= r; ++i){
    t = left_rot((B * (2 * B + 1)) % modulo, log_w, w);
    u = left_rot((D * (2 * D + 1)) % modulo, log_w, w);
    A = left_rot((A ^ t), u, w) + S[2 * i];
    C = left_rot((C ^ u), t, w) + S[2 * i + 1];
    temp = A;
    A = B;
    B = C;
    C = D;
    D = temp;
  }

  A += S[2 * r + 2];
  C += S[2 * r + 3];

  std::cout << "cipher: " << std::hex << A << std::hex << B << std::hex << C << std::hex << D << "\n";
  std::cout << "actual: " << "8fc3a53656b1f778c129df4e9848a41e\n";

  return result;
}

/******************************************************************
 * Function: decrypt
 * Input: <const std::string>
 * Output: std::string
 * Description: decrypt ciphertext from the input string to plaintext
 ******************************************************************/
std::string RC6::decrypt(const std::string &text){
  std::string result;
  
  unsigned int A, B, C, D;
  A = strtoul(text.substr(0, 8).c_str(), NULL, 16);
  B = strtoul(text.substr(8, 8).c_str(), NULL, 16);
  C = strtoul(text.substr(16, 8).c_str(), NULL, 16);
  D = strtoul(text.substr(24, 8).c_str(), NULL, 16);

  std::cout << "text: " << text << "\n";
  std::cout << "A: " << std::hex << A << "\n";
  std::cout << "B: " << std::hex << B << "\n";
  std::cout << "C: " << std::hex << C << "\n";
  std::cout << "D: " << std::hex << D << "\n\n";  

  
  unsigned int t, u, temp;  
  
  C -= S[2 * r + 3];
  A -= S[2 * r + 2];
  for(int i = r; i >= 1; --i){
    temp = D;
    D = C;
    C = B;
    B = A;
    A = temp;
    u = left_rot((D * (2 * D + 1)) % modulo, log_w, w);
    t = left_rot((B * (2 * B + 1)) % modulo, log_w, w);
    C = right_rot((C - S[2 * i + 1]) % modulo, t, w) ^ u;
    A = right_rot((A - S[2 * i]) % modulo, u, w) ^ t;
  }
  D -= S[1];
  B -= S[0];

  std::cout << "plaint: " << std::hex << A << std::hex << B << std::hex << C << std::hex << D << "\n";
  std::cout << "actual: " << "00000000000000000000000000000000\n";
  return result;
}



std::string RC6::run(const std::string &mode, const std::string &text, const std::string &key){

  std::string result;

  key_schedule(key);

  std::cout << "\n";
  std::cout << "mode: " << mode << "\n";
  std::cout << "text: " << text << "\n";
  std::cout << "key: " << key << "\n";
  std::cout << "\n" << std::dec;
  std::cout << "w: " << w << "\n";
  std::cout << "r: " << r << "\n";
  std::cout << "b: " << b << "\n";
  std::cout << "log w: " << log_w << "\n";
  std::cout << "modulo: " << modulo << "\n";

  unsigned int orig = 0x0B7654321;
  unsigned int left = left_rot(orig, 5, w);
  unsigned int right = right_rot(left, 165, w);
  std::cout << "\norig: " << std::hex << orig << std::endl;
  std::cout << "left: " << std::hex << left << std::endl;
  std::cout << "rite: " << std::hex << right << std::endl;

  std::string un_end = "0A0B0CAF2025F2";
  std::string lil_end = little_endian(un_end);
  std::cout << "\noriginal: " << un_end << "\nlittle endian: " << lil_end << "\n";

  std::cout << "\nL[ ]:\n";
  for(int i = 0; i < (b / (w / 8)); i++){
    std::cout << std::hex << L[i] << " ";
  }

  std::cout << "\nS[ ]:\n";
  for(int i = 0; i < (2 * r + 4); i++){
    std::cout << "[" << std::dec << i << "]" << std::hex << S[i] << "\n";
  }

  std::cout << "\n\n";

  
  if(mode.compare(0, strlen("Encryption"), "Encryption") == 0){
    result = encrypt(text);
  }else if(mode.compare(0, strlen("Decryption"), "Decryption") == 0){
    result = decrypt(text);
  }

  
  int n = 1;
  // little endian if true
  if(*(char *)&n == 1) { 
    std::cout << "\nThis machine is little endian\n";
  }else{
    std::cout << "\nThis machine is big endian\n";
  }

  return result;
}

RC6::~RC6(){
  delete S;
}
