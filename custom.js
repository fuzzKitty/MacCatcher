// Copyright 2011-2014, Mike Shema <mike@deadliestwebattacks.com>
var Crypto = {};

Crypto.sha1_hmac = function (msg, key) {
    "use strict";
    var oKeyPad, iKeyPad, iPadRes, bytes, i, len;
    if (key.length > 64) {
        // keys longer than blocksize are shortened
        key = Crypto.sha1(key, true);
    }

    bytes = [];
    len = key.length;
    for (i = 0; i < 64; ++i) {
        bytes[i] = len > i ? key.charCodeAt(i) : 0x00;
    }

    oKeyPad = "";
    iKeyPad = "";

    for (i = 0; i < 64; ++i) {
        oKeyPad += String.fromCharCode(bytes[i] ^ 0x5C);
        iKeyPad += String.fromCharCode(bytes[i] ^ 0x36);
    }

    iPadRes = Crypto.sha1(iKeyPad + msg, true);

    return Crypto.sha1(oKeyPad + iPadRes);
};

Crypto.sha1 = function (msg, raw) {
    function rotate_left(n,s) {
        var t4 = ( n<<s ) | (n>>>(32-s));
        return t4;
    }

    function lsb_hex(val) {
        var str="";
        var i;
        var vh;
        var vl;

        for( i=0; i<=6; i+=2 ) {
            vh = (val>>>(i*4+4))&0x0f;
            vl = (val>>>(i*4))&0x0f;
            str += vh.toString(16) + vl.toString(16);
        }
        return str;
    }

    function cvt_hex(val, raw) {
        var str="";
        var i;
        var v;

        for( i=7; i>=0; i-- ) {
            v = (val>>>(i*4))&0x0f;
            str += raw ? String.fromCharCode(v) : v.toString(16);
        }
        return str;
    }

    var blockstart;
    var i, j;
    var W = new Array(80);
    var H0 = 0x67452301;
    var H1 = 0xEFCDAB89;
    var H2 = 0x98BADCFE;
    var H3 = 0x10325476;
    var H4 = 0xC3D2E1F0;
    var A, B, C, D, E;
    var result, rawResult;

    var msg_len = msg.length;

    var word_array = [];
    for( i=0; i<msg_len-3; i+=4 ) {
        j = msg.charCodeAt(i)<<24 | msg.charCodeAt(i+1)<<16 |
        msg.charCodeAt(i+2)<<8 | msg.charCodeAt(i+3);
        word_array.push( j );
    }

    switch( msg_len % 4 ) {
        case 0:
            i = 0x080000000;
        break;
        case 1:
            i = msg.charCodeAt(msg_len-1)<<24 | 0x0800000;
        break;

        case 2:
            i = msg.charCodeAt(msg_len-2)<<24 | msg.charCodeAt(msg_len-1)<<16 | 0x08000;
        break;

        case 3:
            i = msg.charCodeAt(msg_len-3)<<24 | msg.charCodeAt(msg_len-2)<<16 | msg.charCodeAt(msg_len-1)<<8    | 0x80;
        break;
    }

    word_array.push( i );

    while( (word_array.length % 16) != 14 ) word_array.push( 0 );

    word_array.push( msg_len>>>29 );
    word_array.push( (msg_len<<3)&0x0ffffffff );

    for ( blockstart=0; blockstart<word_array.length; blockstart+=16 ) {
        for( i=0; i<16; i++ ) W[i] = word_array[blockstart+i];
        for( i=16; i<=79; i++ ) W[i] = rotate_left(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);

        A = H0;
        B = H1;
        C = H2;
        D = H3;
        E = H4;

        for( i= 0; i<=19; i++ ) {
            temp = (rotate_left(A,5) + ((B&C) | (~B&D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B,30);
            B = A;
            A = temp;
        }

        for( i=20; i<=39; i++ ) {
            temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B,30);
            B = A;
            A = temp;
        }

        for( i=40; i<=59; i++ ) {
            temp = (rotate_left(A,5) + ((B&C) | (B&D) | (C&D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B,30);
            B = A;
            A = temp;
        }

        for( i=60; i<=79; i++ ) {
            temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B,30);
            B = A;
            A = temp;
        }

        H0 = (H0 + A) & 0x0ffffffff;
        H1 = (H1 + B) & 0x0ffffffff;
        H2 = (H2 + C) & 0x0ffffffff;
        H3 = (H3 + D) & 0x0ffffffff;
        H4 = (H4 + E) & 0x0ffffffff;
    }

    result = (cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4)).toLowerCase();

    if (!raw) {
        return result;
    }

    rawResult = "";
    while (result.length) {
        rawResult += String.fromCharCode(parseInt(result.substr(0, 2), 16));
        result = result.substr(2);
    }
    return rawResult;
};


function hex_to_ascii(str1){
      var hex  = str1.toString();
      var str = '';
      for (var n = 0; n < hex.length; n += 2) {
          str += String.fromCharCode(parseInt(hex.substr(n, 2), 16));
      }
      return str;
}


function capabilityChecks() {
  return 'undefined' != typeof(ArrayBuffer);
}

function Component(id, d, s) {
  this.m_depth = d;
  this.m_id = id;
  this.m_string = s;

  this.depth = function() {
    return this.m_depth;
  }

  this.str = function() {
    return this.m_string;
  }
}

function ViewState(inBase64) {
  this.m_base64 = inBase64;
  this.m_raw = atob(inBase64);
  this.m_bytes = new Uint8Array(new ArrayBuffer(this.m_raw.length));
  this.m_depth = 0;
  this.m_position = 0;
  this.m_components = [];

  for(var i = 0; i < this.m_raw.length; ++i) {
    this.m_bytes[i] = this.m_raw.charCodeAt(i);
  }

  this.isValid = function() {
    return 0xff == this.m_bytes[0] && 0x01 == this.m_bytes[1];
  }

  this.components = function() {
    return this.m_components;
  }

  this.consume = function() {
    this.m_position = 2;
    this.parse()
    var n = this.m_bytes.length - this.m_position;
    if(20 == n)
      this.pushComponent("SHA1", "SHA1");
    else if(16 == n)
      this.pushComponent("MD5", "MD5");
	else if(32 == n)
      this.pushComponent("SHA256", "SHA256");
	else if(0 == n)
      this.pushComponent("NO_MAC", "NO_MAC");

  }

  this.parse = function() {
    ++this.m_depth;
    var f = this.foo[this.m_bytes[this.m_position]];
    if('function' === typeof(f)) {
      f(this);
    }
    else {
      this.pushComponent("byte", "byte " + this.m_bytes[this.m_position]);
      ++this.m_position;
    }
    --this.m_depth;
  }

  this.parseContainer = function(o, s) {
    ++o.m_position;
    var n = o.parseUInteger32(o);
    o.pushComponent("array", "array (" + n + ")");
    ++o.m_depth;
    while(n > 0) {
      o.parse();
      --n;
    }
    --o.m_depth;
  }

  this.parseString = function(o) {
    var n = o.parseUInteger32(o) + o.m_position;
    var s = "";

    while(o.m_position < n) {
      s += String.fromCharCode(parseInt(o.m_bytes[o.m_position]));
      ++o.m_position;
    }

    return s;
  }

  this.parseUInteger32 = function(o) {
    var n = 0;
    var bits = 0;
    while(bits < 32) {
      var b = parseInt(o.m_bytes[o.m_position]);
      ++o.m_position;
      n |= (b & 0x7f) << bits;
      if(!(b & 0x80)) {
        return n;
      }
      bits += 7;
    }
    // overflow
    return n;
  }

  this.parseType = function(o) {
    var flag = this.m_bytes[this.m_position];
    if(flag == 0x29 || flag == 0x2a) {
      ++o.m_position;
      return o.parseString(o);
    }
    else if(flag == 0x2b) {
      ++o.m_position;
      return o.parseUInteger32(o);
    }
    else {
      return "?";
    }
  }

  this.pushComponent = function(id, s) {
    var c = new Component(id, this.m_depth, s);
    this.m_components.push(c);
  }
}

ViewState.prototype.foo = {};
ViewState.prototype.foo[0x02] = function(o) {
  ++o.m_position;
  var n = o.parseUInteger32(o);
  o.pushComponent("", n);
}
ViewState.prototype.foo[0x03] = function(o) {
  // XXX should be a single byte
  o.parseContainer(o, "Booleans");
}
ViewState.prototype.foo[0x05] = function(o) {
  ++o.m_position;
  var s = o.parseString(o);
  o.pushComponent("string", s);
}
ViewState.prototype.foo[0x06] = function(o) {
  ++o.m_position;
  o.pushComponent("datetime", "datetime");
  o.m_position += 8;
}
ViewState.prototype.foo[0x09] = function(o) {
  ++o.m_position;
  o.pushComponent("RGBA", "RGBA");
  o.m_position += 4;
}
ViewState.prototype.foo[0x0b] = function(o) {
  ++o.m_position;
  var s = String("");
  if(0x29 == o.m_bytes[o.m_position]) {
    ++o.m_position; // 0x01
    var n = o.parseUInteger32(o);
    while(n > 0) {
      s += String.fromCharCode(parseInt(o.m_bytes[o.m_position]));
      ++o.m_position;
      --n;
    }
    ++o.m_position; // 0x02
    o.parse();
    o.parse();
  }
  else {
    while(0x00 != o.m_bytes[o.m_position]) {
      s += String.fromCharCode(parseInt(o.m_bytes[o.m_position]));
      ++o.m_position;
    }
    ++o.m_position;
  }
  o.pushComponent("string", s);
}
ViewState.prototype.foo[0x0f] = function(o) {
  o.update(o, "pair ");
  o.parse(); o.parse();
}
ViewState.prototype.foo[0x10] = function(o) {
  o.update(o, "triplet");
  o.parse(); o.parse(); o.parse();
}
ViewState.prototype.foo[0x14] = function(o) {
  ++o.m_position;
  var type = o.parseType(o);
  var n = o.parseUInteger32(o);
  o.pushComponent("array", "array (" + n + ")");
  ++o.m_depth;
  o.pushComponent("type", "type " + type);
  while(n > 0) {
    o.parse();
    --n;
  }
  --o.m_depth;
}
ViewState.prototype.foo[0x15] = function(o) {
  ++o.m_position;
  var n = o.parseUInteger32(o);
  o.pushComponent("array", "string array (" + n + ")");
  ++o.m_depth;
  var sa = [];
  while(n > 0) {
    if(0x00 == o.m_bytes[o.m_position]) {
      ++o.m_position;
      o.pushComponent("empty", "NULL");
    }
    else
      o.pushComponent("string", o.parseString(o));
    --n;
  }
  --o.m_depth;
}
ViewState.prototype.foo[0x16] = function(o) {
  // XXX the official name is "arraylist"
  o.parseContainer(o, "objects");
}
ViewState.prototype.foo[0x18] = function(o) {
    ++o.m_position;
    var n = o.parseUInteger32(o);
    o.pushComponent("cs", "control state (" + n + ")");
    ++o.m_depth;
    while(n > 0) {
      o.parse();
      o.parse();
      --n;
    }
    --o.m_depth;
}
ViewState.prototype.foo[0x1b] = function(o) {
  o.update(o, "unit");
  o.m_position += 12;
}
ViewState.prototype.foo[0x1e] = ViewState.prototype.foo[0x05];
ViewState.prototype.foo[0x1f] = function(o) {
  ++o.m_position;
  var n = o.parseUInteger32(o);
  o.pushComponent("stringref", "stringref (" + n + ")");
}
ViewState.prototype.foo[0x24] = function(o) {
  ++o.m_position;
  o.pushComponent("UUID", "UUID");
  o.m_position += 36;
}
ViewState.prototype.foo[0x3c] = function(o) {
  ++o.m_position;
  var type = o.parseType(o);
  var length = o.parseUInteger32(o);
  var n = o.parseUInteger32(o);
  o.pushComponent("sparsearray", "sparsearray (" + n + ")");
  ++o.m_depth;
  o.pushComponent("type", "type " + type);
  while(n > 0) {
    var index = o.parseUInteger32(o);
    o.pushComponent("index", "index " + index);
    o.parse();
    --n;
  }
  --o.m_depth;
}
ViewState.prototype.foo[0x64] = function(o) { o.update(o, "{empty}"); }
ViewState.prototype.foo[0x65] = function(o) { o.update(o, "{empty string}"); }
ViewState.prototype.foo[0x66] = function(o) { o.update(o, "number: 0"); }
ViewState.prototype.foo[0x67] = function(o) { o.update(o, "true"); }
ViewState.prototype.foo[0x68] = function(o) { o.update(o, "false"); }
ViewState.prototype.update = function(o, s) { ++o.m_position; o.pushComponent(s, s); }



var page_content = document.documentElement.innerHTML;
var viewstate_reg = "__VIEWSTATE\" value=\"";
if(page_content.includes(viewstate_reg)){
	var view_str = page_content.substr(page_content.indexOf(viewstate_reg));
	view_str = view_str.replace(viewstate_reg, "");
	view_str = view_str.split("\"")[0];
	
	var vs = new ViewState(view_str);
      if(vs.isValid) {
        vs.consume();
        var mac_res = vs.components()[vs.components().length - 1].m_string;
		if(mac_res == "NO_MAC"){
			alert("No MAC Bitches!!!!!");
		}else{
		var generator_reg = "__VIEWSTATEGENERATOR\" value=\"";
		if(page_content.includes(generator_reg)){
			var generator_str = page_content.substr(page_content.indexOf(generator_reg));
			generator_str = generator_str.replace(generator_reg, "");
			generator_str = generator_str.split("\"")[0];
			generator_str_hex = generator_str[6] + generator_str[7] + generator_str[4] + generator_str[5] + generator_str[2] + generator_str[3] + generator_str[0] + generator_str[1];
			var val_keys = ["CB8860CE588A62A2CF9B0B2F48D2C8C31A6A40F0517268CEBCA431A3177B08FC53D818B82DEDCF015A71A0C4B817EA8FDCA2B3BDD091D89F2EDDFB3C06C0CB32,2CC8E5C3B1812451A707FBAAAEAC9052E05AE1B858993660"]
			if(mac_res == "SHA1"){
				var hashSize = 20;
				var enc_data = atob(view_str);
				var dataSize = enc_data.length - hashSize;
				var data_to_hash = enc_data.substr(0, enc_data.length - hashSize) + hex_to_ascii(generator_str_hex);
				for (let i = 0; i < val_keys.length; i++) {
					if(val_keys[i].split(",").length == 2){
						var val_key = val_keys[i].split(",")[0];
						var dec_key = val_keys[i].split(",")[1];
						var test_key = hex_to_ascii(val_key);
						var computed_hash = Crypto.sha1_hmac(data_to_hash, test_key);
						if(hex_to_ascii(computed_hash) == enc_data.substr(enc_data.length - 20)){
							alert("Awwwwwwww Snap!!!!!!\nDecription Key: " + dec_key + "\nValidation Key: " + val_key);
							console.log("Awwwwwwww Snap!!!!!!\nDecription Key: " + dec_key + "\nValidation Key: " + val_key);
						}
					}
				}
			
			}
		}



}
      }
	  
	  
}
