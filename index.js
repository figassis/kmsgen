/*jshint esversion: 6 */
var request = require('request');
var AWS = require('aws-sdk');
var uuid = require('uuid');

AWS.config.update({
    region: 'us-east-1'
});
var kms = new AWS.KMS({
    region: 'us-east-1',
    apiVersion: '2014-11-01'
});

var sts = new AWS.STS({
    apiVersion: '2011-06-15'
});

var options = {
    url: 'https://s3.amazonaws.com/bvnk.nellcorp.com/kms_policy.json',
    headers: {
        'User-Agent': 'request'
    }
};

exports.handler = (event, context, callback) => {

    //console.log('Received event:', JSON.stringify(event, null, 2));
    var token = (event.hasOwnProperty('token')) ? event.token : '';
    var domain = (event.hasOwnProperty('domain')) ? event.domain.toLowerCase() : '';
    var origin = (event.hasOwnProperty('origin')) ? event.origin : '';
    var alias = domain + "/" + origin;
    alias = 'alias/' + alias.replace(/\./g, "-");

    var params = {};
    sts.getCallerIdentity(params, function(err, data) {
        if (err) callback(JSON.stringify({
            "reason": "auth_error",
            "errors": "Could not retrieve account ID. Please check credentials."
        }));

        //data = { Account: "123456789012",  Arn: "arn:aws:iam::123456789012:user/Alice",  UserId: "AKIAI44QH8DHBEXAMPLE" }

        request(options, function(error, response, body) {
            if (error || response.statusCode != 200) callback(JSON.stringify({
                "reason": "server_error",
                "errors": ["Could not retrieve policy."]
            }));

            var policy = JSON.parse(body);
            policy.Statement[0].Principal.AWS = "arn:aws:iam::" + data.Account + ":root";
            policy.Statement[1].Principal.AWS = "arn:aws:iam::" + data.Account + ":user/KMS_ADMIN";
            policy.Statement[2].Principal.AWS = "arn:aws:iam::" + data.Account + ":user/bvnk";

            kms.listKeys({}, function(err, keylist) {
                if (err) {
                    callback(JSON.stringify({
                        "reason": "server_error",
                        "errors": "Could not retrieve account ID. Please check credentials."
                    }));
                } else {
                    if (keylist.Keys.length >= 50) {
                        callback(JSON.stringify({
                            "reason": "auth_error",
                            "errors": "BVNK has created too many Keys! Please ask the administrator to delete a few. It might take a week."
                        }));
                    } else {
                        // Get the object from the event and show its content type
                        var keyparams = {
                            BypassPolicyLockoutSafetyCheck: true,
                            Description: 'BVNK CMK created by ' + domain + '/' + origin,
                            KeyUsage: 'ENCRYPT_DECRYPT',
                            Origin: 'AWS_KMS',
                            Policy: JSON.stringify(policy),
                            Tags: [{
                                TagKey: 'CreatedBy',
                                TagValue: domain + '/' + origin
                            }, {
                                TagKey: 'Reason',
                                TagValue: 'BVNK'
                            }]
                        };

                        kms.createKey(keyparams, function(err, keydata) {
                            if (err) {
                                if (err) {
                                    callback(JSON.stringify({
                                        "reason": "server_error",
                                        "errors": "Could not create Customer Master Key."
                                    }));
                                }
                            } else {
                                var aliasparams = {
                                    AliasName: alias,
                                    TargetKeyId: keydata.KeyMetadata.KeyId
                                };

                                kms.createAlias(aliasparams, function(err, data) {
                                    if (err) {
                                        callback(JSON.stringify({
                                            "reason": "server_error",
                                            "errors": "Could not create key alias. This is probably a duplicate request."
                                        }));
                                    } else {
                                        callback(null, {
                                            KeyAlias: alias
                                        });
                                    }
                                });
                            }
                        });
                    }
                }
            });
        });
    });
};