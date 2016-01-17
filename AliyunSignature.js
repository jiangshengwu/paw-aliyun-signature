(function() {
    var CryptoJS = require("crypto-js");

    String.prototype.format = function(args) {
        var result = this;
        if (arguments.length > 0) {
            if (arguments.length == 1 && typeof (args) == "object") {
                for (var key in args) {
                    if(args[key]!=undefined){
                        var reg = new RegExp("({" + key + "})", "g");
                        result = result.replace(reg, args[key]);
                    }
                }
            }
            else {
                for (var i = 0; i < arguments.length; i++) {
                    if (arguments[i] != undefined) {
                        var reg = new RegExp("({[" + i + "]})", "g");
                        result = result.replace(reg, arguments[i]);
                    }
                }
            }
        }
        return result;
    };

    var pad = function(number) {
        var r = String(number);
        if (r.length === 1) {
            r = '0' + r;
        }
        return r;
    };

    Date.prototype.toISOString = function() {
        return this.getUTCFullYear()
            + '-' + pad(this.getUTCMonth() + 1)
            + '-' + pad(this.getUTCDate())
            + 'T' + pad(this.getUTCHours())
            + ':' + pad(this.getUTCMinutes())
            + ':' + pad(this.getUTCSeconds())
            + 'Z';
    };

    var CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
    Math.uuid = function() {
        var uuid = new Array(36), rnd = 0, r;
        for (var i = 0; i < 36; i++) {
            if (i==8 || i==13 ||  i==18 || i==23) {
                uuid[i] = '-';
            } else if (i==14) {
                uuid[i] = '4';
            } else {
                if (rnd <= 0x02) rnd = 0x2000000 + (Math.random()*0x1000000)|0;
                r = rnd & 0xf;
                rnd = rnd >> 4;
                uuid[i] = CHARS[(i == 19) ? (r & 0x3) | 0x8 : r];
            }
        }
        return uuid.join('');
    };

    var identifier = 'com.weibo.api.AliyunSignature';

    var AliyunSignature = function() {
        var sep = '&';
        var httpMethod = 'GET';
        var percentEncode = function(s) {
            s = encodeURIComponent(s);
            s = s.replace(/\+/g, '%20');
            s = s.replace(/\*/g, '%2A');
            s = s.replace(/%7E/g, '~');
            return s;
        };
        var getQueryWithSignature = function(userParams, commonParams, keySecret) {
            var kvs = (userParams + sep + commonParams).split(sep);
            var keys = [];
            var params = {};
            for (var i = 0; i < kvs.length; i++) {
                var arr = kvs[i].split('=');
                if (arr.length != 2) {
                    return '';
                }
                keys.push(arr[0]);
                params[arr[0]] = arr[1];
            }
            keys.sort();
            var sortedParams = [];
            for (var i = 0; i < keys.length; i++) {
                var encodeKey = percentEncode(keys[i]);
                var encodeValue = percentEncode(params[keys[i]]);
                sortedParams.push(encodeKey + '=' + encodeValue)
            }
            var canonicalized = percentEncode(sortedParams.join(sep));
            var strToSign = httpMethod + sep + percentEncode('/') + sep + canonicalized;
            var hash = CryptoJS.HmacSHA1(strToSign, keySecret +sep);
            var sign = CryptoJS.enc.Base64.stringify(hash);
            return percentEncode(sign) + sep + commonParams;
        };
        var getUserParameters = function(request) {
            var ds = request.getUrl(true);
            var newDs = DynamicString();
            var components = ds.components;
            for (var i = 0; i < ds.length; i ++) {
                var c = components[i];
                if (c) {
                    if (typeof c === 'string') {
                        newDs.appendString(c);
                    } else {
                        if (c.type != identifier) {
                            newDs.appendDynamicValue(c);
                        }
                    }
                }
            }
            var str = newDs.getEvaluatedString();
            return str.replace(/^http.*?\?/, '').replace(/Signature=&?/, '').replace(/^&|&$/, '');
        };

        this.evaluate = function(context) {
            var userParams = getUserParameters(context.getCurrentRequest());
            var keyId = this.keyId;
            var keySecret = this.keySecret;
            var resourceOwnerAccount = this.resourceOwnerAccount;
            var format = 'JSON';
            if (this.format != '') {
                format = this.format;
            }
            var version = '2014-05-26';
            var signatureMethod = 'HMAC-SHA1';
            var signatureVersion = '1.0';
            var timeStamp = new Date().toISOString();
            var signatureNonce = Math.uuid();
            var commonParams = ('Format={format}&Version={version}'
                + '&AccessKeyId={keyId}&SignatureMethod={signatureMethod}'
                + '&SignatureVersion={signatureVersion}&'
                + 'SignatureNonce={signatureNonce}&TimeStamp={timeStamp}').format({
                format: format,
                version: version,
                keyId: keyId,
                signatureMethod: signatureMethod,
                signatureVersion: signatureVersion,
                signatureNonce: signatureNonce,
                timeStamp: timeStamp
            });
            if (resourceOwnerAccount != '') {
                commonParams += '&ResourceOwnerAccount=' + resourceOwnerAccount
            }
            return getQueryWithSignature(userParams, commonParams, keySecret);
        };
    };

    AliyunSignature.identifier = identifier;
    AliyunSignature.title = "Aliyun Signature";
    AliyunSignature.inputs = [
        DynamicValueInput("keyId", "Access Key Id", "String"),
        DynamicValueInput("keySecret", "Access Key Secret", "String"),
        DynamicValueInput("resourceOwnerAccount", "Resource Owner Account", "String"),
        DynamicValueInput("format", "Format", "String")
    ];
    registerDynamicValueClass(AliyunSignature);
}).call(this);
