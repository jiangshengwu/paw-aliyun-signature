(function() {

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

        var percentEncode = function(s) {
            s = encodeURIComponent(s);
            s = percent(s);
            return s;
        };
        var percent = function(s) {
            s = s.replace(/\+/g, '%20');
            s = s.replace(/\*/g, '%2A');
            s = s.replace(/%7E/g, '~');
            return s;
        };

        var signParams = function(httpMethod, userParams, keySecret) {
            var kvs = userParams.replace(/^&|&$/, '').split(sep);
            var keys = [];
            var params = {};
            for (var i = 0; i < kvs.length; i++) {
                var arr = kvs[i].split('=');
                if (arr.length != 2) {
                    continue;
                }
                keys.push(arr[0]);
                params[arr[0]] = arr[1];
            }
            keys.sort();
            var sortedParams = [];
            for (var i = 0; i < keys.length; i++) {
                var encodeKey = percentEncode(keys[i]);
                var encodeValue = percent(params[keys[i]]);
                sortedParams.push(encodeKey + '=' + encodeValue)
            }
            var canonicalized = percentEncode(sortedParams.join(sep));
            var strToSign = httpMethod + sep + percentEncode('/') + sep + canonicalized;

            var dynamicValue = DynamicValue('com.luckymarmot.HMACDynamicValue', {
                'input': strToSign,
                'key': keySecret +sep,
                'algorithm':1 // HMAC-SHA1
                });

            return DynamicString(dynamicValue).getEvaluatedString();
        };
        var getUserParametersFromUrl = function(request) {
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
            return str.replace(/^https?:\/\/[^\/]+[\/\?]*/, '').replace(/Signature=&?/, '').replace(/^&|&$/, '');
        };
        var getUserParametersFromBody = function(request) {
            var params = [];
            var bodyParameters = request.getUrlEncodedBody(true);
            for (var key in bodyParameters) {
                if (key=="Signature") {
                    continue;
                }
                var value = bodyParameters[key]; // DynamicString
                params.push("" + key + "=" + encodeURIComponent(value.getEvaluatedString()));
            }
            return params.join(sep);
        };

        var evaluateGet = function(env, request) {
            var httpMethod = request.method;
            var userParams = getUserParametersFromUrl(request) + sep + getUserParametersFromBody(request);
            var keyId = env.keyId;
            var keySecret = env.keySecret;
            var resourceOwnerAccount = env.resourceOwnerAccount;
            var format = 'JSON';
            if (env.format != '') {
                format = env.format;
            }
            var version = env.version;
            var signatureMethod = 'HMAC-SHA1';
            var signatureVersion = '1.0';
            var timeStamp = new Date().toISOString();
            var signatureNonce = Math.uuid();
            var commonParams = ('Format={format}&Version={version}'
                + '&AccessKeyId={keyId}&SignatureMethod={signatureMethod}'
                + '&SignatureVersion={signatureVersion}&'
                + 'SignatureNonce={signatureNonce}&Timestamp={timeStamp}').format({
                format: format,
                version: version,
                keyId: keyId,
                signatureMethod: signatureMethod,
                signatureVersion: signatureVersion,
                signatureNonce: signatureNonce,
                timeStamp: encodeURIComponent(timeStamp)
            });
            if (resourceOwnerAccount != '') {
                commonParams += '&ResourceOwnerAccount=' + resourceOwnerAccount
            }

            var signature = signParams(httpMethod, userParams + sep + commonParams, keySecret);
            return encodeURIComponent(signature) + sep + commonParams;
        };
        var evaluatePost = function(env, request) {
            var urlParams = getUserParametersFromUrl(request);
            if (urlParams != '') {
                return evaluateGet(env, request);
            }

            var httpMethod = request.method;
            var userParams = getUserParametersFromBody(request);
            var keySecret = env.keySecret;
            return signParams(httpMethod, userParams, keySecret);
        }

        this.evaluate = function(context) {
            var request = context.getCurrentRequest();
            if (request == undefined) {
                return '';
            }

            var httpMethod = request.method;
            if (httpMethod == "GET") {
                return evaluateGet(this, request);
            } else if (httpMethod == "POST"){
                return evaluatePost(this, request);
            } else {
                return "____Only_Support_GET_POST____";
            }
        };

        this.title = function(context) {
            return "AliyunSignature[" + this.version + "]";
        }
    };

    AliyunSignature.identifier = identifier;
    AliyunSignature.title = "Aliyun Signature";
    AliyunSignature.inputs = [
        DynamicValueInput("keyId", "Access Key Id", "String"),
        DynamicValueInput("keySecret", "Access Key Secret", "String"),
        DynamicValueInput("resourceOwnerAccount", "Resource Owner Account", "String"),
        DynamicValueInput("format", "Format", "String"),
        DynamicValueInput("version", "Version", "String")
    ];
    registerDynamicValueClass(AliyunSignature);
}).call(this);
