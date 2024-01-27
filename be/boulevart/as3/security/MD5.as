package be.boulevart.as3.security 
{
    public class MD5 extends Object
    {
        public function MD5()
        {
            super();
            return;
        }

        public static function md5_gg(arg1:Number, arg2:Number, arg3:Number, arg4:Number, arg5:Number, arg6:Number, arg7:Number):Number
        {
            return md5_cmn(arg2 & arg4 | arg3 & ~arg4, arg1, arg2, arg5, arg6, arg7);
        }

        public static function md5_hh(arg1:Number, arg2:Number, arg3:Number, arg4:Number, arg5:Number, arg6:Number, arg7:Number):Number
        {
            return md5_cmn(arg2 ^ arg3 ^ arg4, arg1, arg2, arg5, arg6, arg7);
        }

        public static function md5_ii(arg1:Number, arg2:Number, arg3:Number, arg4:Number, arg5:Number, arg6:Number, arg7:Number):Number
        {
            return md5_cmn(arg3 ^ (arg2 | ~arg4), arg1, arg2, arg5, arg6, arg7);
        }

        public static function safe_add(arg1:Number, arg2:Number):Number
        {
            var loc1:*=(arg1 & 65535) + (arg2 & 65535);
            var loc2:*=(arg1 >> 16) + (arg2 >> 16) + (loc1 >> 16);
            return loc2 << 16 | loc1 & 65535;
        }

        public static function bit_rol(arg1:Number, arg2:Number):Number
        {
            return arg1 << arg2 | arg1 >>> 32 - arg2;
        }

        
        {
            hexcase = 0;
            b64pad = "";
        }

        public static function encrypt(arg1:String):String
        {
            return hex_md5(arg1);
        }

        public static function hex_md5(arg1:String):String
        {
            return rstr2hex(rstr_md5(str2rstr_utf8(arg1)));
        }

        public static function b64_md5(arg1:String):String
        {
            return rstr2b64(rstr_md5(str2rstr_utf8(arg1)));
        }

        public static function any_md5(arg1:String, arg2:String):String
        {
            return rstr2any(rstr_md5(str2rstr_utf8(arg1)), arg2);
        }

        public static function hex_hmac_md5(arg1:String, arg2:String):String
        {
            return rstr2hex(rstr_hmac_md5(str2rstr_utf8(arg1), str2rstr_utf8(arg2)));
        }

        public static function b64_hmac_md5(arg1:String, arg2:String):String
        {
            return rstr2b64(rstr_hmac_md5(str2rstr_utf8(arg1), str2rstr_utf8(arg2)));
        }

        public static function any_hmac_md5(arg1:String, arg2:String, arg3:String):String
        {
            return rstr2any(rstr_hmac_md5(str2rstr_utf8(arg1), str2rstr_utf8(arg2)), arg3);
        }

        public static function md5_vm_test():Boolean
        {
            return hex_md5("abc") == "900150983cd24fb0d6963f7d28e17f72";
        }

        public static function rstr_md5(arg1:String):String
        {
            return binl2rstr(binl_md5(rstr2binl(arg1), arg1.length * 8));
        }

        public static function rstr_hmac_md5(arg1:String, arg2:String):String
        {
            var loc1:*=rstr2binl(arg1);
            if (loc1.length > 16) 
            {
                loc1 = binl_md5(loc1, arg1.length * 8);
            }
            var loc2:*=new Array(16);
            var loc3:*=new Array(16);
            var loc4:*=0;
            while (loc4 < 16) 
            {
                loc2[loc4] = loc1[loc4] ^ 909522486;
                loc3[loc4] = loc1[loc4] ^ 1549556828;
                ++loc4;
            }
            var loc5:*=binl_md5(loc2.concat(rstr2binl(arg2)), 512 + arg2.length * 8);
            return binl2rstr(binl_md5(loc3.concat(loc5), 512 + 128));
        }

        public static function rstr2hex(arg1:String):String
        {
            var loc3:*=NaN;
            var loc1:*=hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
            var loc2:*="";
            var loc4:*=0;
            while (loc4 < arg1.length) 
            {
                loc3 = arg1.charCodeAt(loc4);
                loc2 = loc2 + (loc1.charAt(loc3 >>> 4 & 15) + loc1.charAt(loc3 & 15));
                ++loc4;
            }
            return loc2;
        }

        public static function rstr2b64(arg1:String):String
        {
            var loc5:*=undefined;
            var loc6:*=NaN;
            var loc1:*="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            var loc2:*="";
            var loc3:*=arg1.length;
            var loc4:*=0;
            while (loc4 < loc3) 
            {
                loc5 = arg1.charCodeAt(loc4) << 16 | (loc4 + 1 < loc3 ? arg1.charCodeAt(loc4 + 1) << 8 : 0) | (loc4 + 2 < loc3 ? arg1.charCodeAt(loc4 + 2) : 0);
                loc6 = 0;
                while (loc6 < 4) 
                {
                    if (loc4 * 8 + loc6 * 6 > arg1.length * 8) 
                    {
                        loc2 = loc2 + b64pad;
                    }
                    else 
                    {
                        loc2 = loc2 + loc1.charAt(loc5 >>> 6 * (3 - loc6) & 63);
                    }
                    ++loc6;
                }
                loc4 = loc4 + 3;
            }
            return loc2;
        }

        public static function rstr2any(arg1:String, arg2:String):String
        {
            var loc3:*=NaN;
            var loc4:*=NaN;
            var loc5:*=NaN;
            var loc6:*=null;
            var loc1:*=arg2.length;
            var loc2:*=[];
            var loc7:*=new Array(arg1.length / 2);
            loc3 = 0;
            while (loc3 < loc7.length) 
            {
                loc7[loc3] = arg1.charCodeAt(loc3 * 2) << 8 | arg1.charCodeAt(loc3 * 2 + 1);
                ++loc3;
            }
            while (loc7.length > 0) 
            {
                loc6 = [];
                loc5 = 0;
                loc3 = 0;
                while (loc3 < loc7.length) 
                {
                    loc5 = (loc5 << 16) + loc7[loc3];
                    loc4 = Math.floor(loc5 / loc1);
                    loc5 = loc5 - loc4 * loc1;
                    if (loc6.length > 0 || loc4 > 0) 
                    {
                        loc6[loc6.length] = loc4;
                    }
                    ++loc3;
                }
                loc2[loc2.length] = loc5;
                loc7 = loc6;
            }
            var loc8:*="";
            loc3 = (loc2.length - 1);
            while (loc3 >= 0) 
            {
                loc8 = loc8 + arg2.charAt(loc2[loc3]);
                --loc3;
            }
            return loc8;
        }

        public static function str2rstr_utf8(arg1:String):String
        {
            var loc3:*=NaN;
            var loc4:*=NaN;
            var loc1:*="";
            var loc2:*=-1;
            while (++loc2 < arg1.length) 
            {
                loc3 = arg1.charCodeAt(loc2);
                loc4 = loc2 + 1 < arg1.length ? arg1.charCodeAt(loc2 + 1) : 0;
                if (55296 <= loc3 && loc3 <= 56319 && 56320 <= loc4 && loc4 <= 57343) 
                {
                    loc3 = 65536 + ((loc3 & 1023) << 10) + (loc4 & 1023);
                    ++loc2;
                }
                if (loc3 <= 127) 
                {
                    loc1 = loc1 + String.fromCharCode(loc3);
                    continue;
                }
                if (loc3 <= 2047) 
                {
                    loc1 = loc1 + String.fromCharCode(192 | loc3 >>> 6 & 31, 128 | loc3 & 63);
                    continue;
                }
                if (loc3 <= 65535) 
                {
                    loc1 = loc1 + String.fromCharCode(224 | loc3 >>> 12 & 15, 128 | loc3 >>> 6 & 63, 128 | loc3 & 63);
                    continue;
                }
                if (!(loc3 <= 2097151)) 
                {
                    continue;
                }
                loc1 = loc1 + String.fromCharCode(240 | loc3 >>> 18 & 7, 128 | loc3 >>> 12 & 63, 128 | loc3 >>> 6 & 63, 128 | loc3 & 63);
            }
            return loc1;
        }

        public static function str2rstr_utf16le(arg1:String):String
        {
            var loc1:*="";
            var loc2:*=0;
            while (loc2 < arg1.length) 
            {
                loc1 = loc1 + String.fromCharCode(arg1.charCodeAt(loc2) & 255, arg1.charCodeAt(loc2) >>> 8 & 255);
                ++loc2;
            }
            return loc1;
        }

        public static function str2rstr_utf16be(arg1:String):String
        {
            var loc1:*="";
            var loc2:*=0;
            while (loc2 < arg1.length) 
            {
                loc1 = loc1 + String.fromCharCode(arg1.charCodeAt(loc2) >>> 8 & 255, arg1.charCodeAt(loc2) & 255);
                ++loc2;
            }
            return loc1;
        }

        public static function rstr2binl(arg1:String):Array
        {
            var loc2:*=NaN;
            var loc1:*=new Array(arg1.length >> 2);
            loc2 = 0;
            while (loc2 < loc1.length) 
            {
                loc1[loc2] = 0;
                ++loc2;
            }
            loc2 = 0;
            while (loc2 < arg1.length * 8) 
            {
                loc1[loc2 >> 5] = loc1[loc2 >> 5] | (arg1.charCodeAt(loc2 / 8) & 255) << loc2 % 32;
                loc2 = loc2 + 8;
            }
            return loc1;
        }

        public static function binl2rstr(arg1:Array):String
        {
            var loc1:*="";
            var loc2:*=0;
            while (loc2 < arg1.length * 32) 
            {
                loc1 = loc1 + String.fromCharCode(arg1[loc2 >> 5] >>> loc2 % 32 & 255);
                loc2 = loc2 + 8;
            }
            return loc1;
        }

        public static function binl_md5(arg1:Array, arg2:Number):Array
        {
            var loc6:*=NaN;
            var loc7:*=NaN;
            var loc8:*=NaN;
            var loc9:*=NaN;
            arg1[arg2 >> 5] = arg1[arg2 >> 5] | 128 << arg2 % 32;
            arg1[(arg2 + 64 >>> 9 << 4) + 14] = arg2;
            var loc1:*=1732584193;
            var loc2:*=-271733879;
            var loc3:*=-1732584194;
            var loc4:*=271733878;
            var loc5:*=0;
            while (loc5 < arg1.length) 
            {
                loc6 = loc1;
                loc7 = loc2;
                loc8 = loc3;
                loc9 = loc4;
                loc1 = md5_ff(loc1, loc2, loc3, loc4, arg1[loc5 + 0], 7, -680876936);
                loc4 = md5_ff(loc4, loc1, loc2, loc3, arg1[loc5 + 1], 12, -389564586);
                loc3 = md5_ff(loc3, loc4, loc1, loc2, arg1[loc5 + 2], 17, 606105819);
                loc2 = md5_ff(loc2, loc3, loc4, loc1, arg1[loc5 + 3], 22, -1044525330);
                loc1 = md5_ff(loc1, loc2, loc3, loc4, arg1[loc5 + 4], 7, -176418897);
                loc4 = md5_ff(loc4, loc1, loc2, loc3, arg1[loc5 + 5], 12, 1200080426);
                loc3 = md5_ff(loc3, loc4, loc1, loc2, arg1[loc5 + 6], 17, -1473231341);
                loc2 = md5_ff(loc2, loc3, loc4, loc1, arg1[loc5 + 7], 22, -45705983);
                loc1 = md5_ff(loc1, loc2, loc3, loc4, arg1[loc5 + 8], 7, 1770035416);
                loc4 = md5_ff(loc4, loc1, loc2, loc3, arg1[loc5 + 9], 12, -1958414417);
                loc3 = md5_ff(loc3, loc4, loc1, loc2, arg1[loc5 + 10], 17, -42063);
                loc2 = md5_ff(loc2, loc3, loc4, loc1, arg1[loc5 + 11], 22, -1990404162);
                loc1 = md5_ff(loc1, loc2, loc3, loc4, arg1[loc5 + 12], 7, 1804603682);
                loc4 = md5_ff(loc4, loc1, loc2, loc3, arg1[loc5 + 13], 12, -40341101);
                loc3 = md5_ff(loc3, loc4, loc1, loc2, arg1[loc5 + 14], 17, -1502002290);
                loc2 = md5_ff(loc2, loc3, loc4, loc1, arg1[loc5 + 15], 22, 1236535329);
                loc1 = md5_gg(loc1, loc2, loc3, loc4, arg1[loc5 + 1], 5, -165796510);
                loc4 = md5_gg(loc4, loc1, loc2, loc3, arg1[loc5 + 6], 9, -1069501632);
                loc3 = md5_gg(loc3, loc4, loc1, loc2, arg1[loc5 + 11], 14, 643717713);
                loc2 = md5_gg(loc2, loc3, loc4, loc1, arg1[loc5 + 0], 20, -373897302);
                loc1 = md5_gg(loc1, loc2, loc3, loc4, arg1[loc5 + 5], 5, -701558691);
                loc4 = md5_gg(loc4, loc1, loc2, loc3, arg1[loc5 + 10], 9, 38016083);
                loc3 = md5_gg(loc3, loc4, loc1, loc2, arg1[loc5 + 15], 14, -660478335);
                loc2 = md5_gg(loc2, loc3, loc4, loc1, arg1[loc5 + 4], 20, -405537848);
                loc1 = md5_gg(loc1, loc2, loc3, loc4, arg1[loc5 + 9], 5, 568446438);
                loc4 = md5_gg(loc4, loc1, loc2, loc3, arg1[loc5 + 14], 9, -1019803690);
                loc3 = md5_gg(loc3, loc4, loc1, loc2, arg1[loc5 + 3], 14, -187363961);
                loc2 = md5_gg(loc2, loc3, loc4, loc1, arg1[loc5 + 8], 20, 1163531501);
                loc1 = md5_gg(loc1, loc2, loc3, loc4, arg1[loc5 + 13], 5, -1444681467);
                loc4 = md5_gg(loc4, loc1, loc2, loc3, arg1[loc5 + 2], 9, -51403784);
                loc3 = md5_gg(loc3, loc4, loc1, loc2, arg1[loc5 + 7], 14, 1735328473);
                loc2 = md5_gg(loc2, loc3, loc4, loc1, arg1[loc5 + 12], 20, -1926607734);
                loc1 = md5_hh(loc1, loc2, loc3, loc4, arg1[loc5 + 5], 4, -378558);
                loc4 = md5_hh(loc4, loc1, loc2, loc3, arg1[loc5 + 8], 11, -2022574463);
                loc3 = md5_hh(loc3, loc4, loc1, loc2, arg1[loc5 + 11], 16, 1839030562);
                loc2 = md5_hh(loc2, loc3, loc4, loc1, arg1[loc5 + 14], 23, -35309556);
                loc1 = md5_hh(loc1, loc2, loc3, loc4, arg1[loc5 + 1], 4, -1530992060);
                loc4 = md5_hh(loc4, loc1, loc2, loc3, arg1[loc5 + 4], 11, 1272893353);
                loc3 = md5_hh(loc3, loc4, loc1, loc2, arg1[loc5 + 7], 16, -155497632);
                loc2 = md5_hh(loc2, loc3, loc4, loc1, arg1[loc5 + 10], 23, -1094730640);
                loc1 = md5_hh(loc1, loc2, loc3, loc4, arg1[loc5 + 13], 4, 681279174);
                loc4 = md5_hh(loc4, loc1, loc2, loc3, arg1[loc5 + 0], 11, -358537222);
                loc3 = md5_hh(loc3, loc4, loc1, loc2, arg1[loc5 + 3], 16, -722521979);
                loc2 = md5_hh(loc2, loc3, loc4, loc1, arg1[loc5 + 6], 23, 76029189);
                loc1 = md5_hh(loc1, loc2, loc3, loc4, arg1[loc5 + 9], 4, -640364487);
                loc4 = md5_hh(loc4, loc1, loc2, loc3, arg1[loc5 + 12], 11, -421815835);
                loc3 = md5_hh(loc3, loc4, loc1, loc2, arg1[loc5 + 15], 16, 530742520);
                loc2 = md5_hh(loc2, loc3, loc4, loc1, arg1[loc5 + 2], 23, -995338651);
                loc1 = md5_ii(loc1, loc2, loc3, loc4, arg1[loc5 + 0], 6, -198630844);
                loc4 = md5_ii(loc4, loc1, loc2, loc3, arg1[loc5 + 7], 10, 1126891415);
                loc3 = md5_ii(loc3, loc4, loc1, loc2, arg1[loc5 + 14], 15, -1416354905);
                loc2 = md5_ii(loc2, loc3, loc4, loc1, arg1[loc5 + 5], 21, -57434055);
                loc1 = md5_ii(loc1, loc2, loc3, loc4, arg1[loc5 + 12], 6, 1700485571);
                loc4 = md5_ii(loc4, loc1, loc2, loc3, arg1[loc5 + 3], 10, -1894986606);
                loc3 = md5_ii(loc3, loc4, loc1, loc2, arg1[loc5 + 10], 15, -1051523);
                loc2 = md5_ii(loc2, loc3, loc4, loc1, arg1[loc5 + 1], 21, -2054922799);
                loc1 = md5_ii(loc1, loc2, loc3, loc4, arg1[loc5 + 8], 6, 1873313359);
                loc4 = md5_ii(loc4, loc1, loc2, loc3, arg1[loc5 + 15], 10, -30611744);
                loc3 = md5_ii(loc3, loc4, loc1, loc2, arg1[loc5 + 6], 15, -1560198380);
                loc2 = md5_ii(loc2, loc3, loc4, loc1, arg1[loc5 + 13], 21, 1309151649);
                loc1 = md5_ii(loc1, loc2, loc3, loc4, arg1[loc5 + 4], 6, -145523070);
                loc4 = md5_ii(loc4, loc1, loc2, loc3, arg1[loc5 + 11], 10, -1120210379);
                loc3 = md5_ii(loc3, loc4, loc1, loc2, arg1[loc5 + 2], 15, 718787259);
                loc2 = md5_ii(loc2, loc3, loc4, loc1, arg1[loc5 + 9], 21, -343485551);
                loc1 = safe_add(loc1, loc6);
                loc2 = safe_add(loc2, loc7);
                loc3 = safe_add(loc3, loc8);
                loc4 = safe_add(loc4, loc9);
                loc5 = loc5 + 16;
            }
            return [loc1, loc2, loc3, loc4];
        }

        public static function md5_cmn(arg1:Number, arg2:Number, arg3:Number, arg4:Number, arg5:Number, arg6:Number):Number
        {
            return safe_add(bit_rol(safe_add(safe_add(arg2, arg1), safe_add(arg4, arg6)), arg5), arg3);
        }

        public static function md5_ff(arg1:Number, arg2:Number, arg3:Number, arg4:Number, arg5:Number, arg6:Number, arg7:Number):Number
        {
            return md5_cmn(arg2 & arg3 | ~arg2 & arg4, arg1, arg2, arg5, arg6, arg7);
        }

        public static const HEX_FORMAT_LOWERCASE:uint=0;

        public static const HEX_FORMAT_UPPERCASE:uint=1;

        public static const BASE64_PAD_CHARACTER_DEFAULT_COMPLIANCE:String="";

        public static const BASE64_PAD_CHARACTER_RFC_COMPLIANCE:String="=";

        public static var hexcase:uint=0;

        public static var b64pad:String="";
    }
}
