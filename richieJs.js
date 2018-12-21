(function(){
	var RapidDevelopmentFramework ={
		
		//通过JS 来进行获取JS 的本地的时间 例如 2017/6/25/19:34
			GetDateTimeString: function () {
				//获取当前的时间
				let date = new Date();
				let seperator1 = "-";
				let seperator2 = ":";
				let month = date.getMonth() + 1;
				let strDate = date.getDate();
				if (month >= 1 && month <= 9){
					month = "0" + month;
				}
				if (strDate >= 0 && strDate <= 9){
					strDate = "0" + strDate;
				}
				let currentdate = date.getFullYear() + seperator1 + month + seperator1 + strDate + " " + date.getHours() + seperator2 + date.getMinutes() + seperator2 + date.getSeconds();//进行获取本地的时间的年月日以及时分秒
	
				if(currentdate!=null && currentdate!=""){
					return currentdate;
				}
				return "";
			},
			//获取本地的经度以及纬度火星文进行获取
	        GetLocation:function(_LocationID){
	            var Location= document.getElementById("_LocationID");
	            function getLocation() {
	                if (navigator.geolocation)
	                {
	                    navigator.geolocation.getCurrentPosition(showPosition);
	                }
	                else
	                {
	                   Location.innerHTML = "此浏览器暂时不支持！";
	                }
	            }
	            function showPosition(position)
	            {
	                Location.innerHTML = "Latitude: " + position.coords.latitude + "<br />Longitude: " + position.coords.longitude;
	            }
	        },
			//通用的验证 手机 电话 以及数字 IP 地址  脚本 以及HTML和 密码 特殊的字符 以及SQL 注入 JS 注入等等
	        Validate: {
	            //检查手机号码格式
	            CheckPhone: function (_MPhoneNumber) {
	                var filter = /(^13\d{9}$)|(^14)[5,7]\d{8}$|(^15[0,1,2,3,5,6,7,8,9]\d{8}$)|(^17)[6,7,8]\d{8}$|(^18\d{9}$)/g;
	                return filter.test($.trim(_MPhoneNumber));
	            },
	            //检查固定电话格式
	            CheckTelephone: function (_MPhoneNumber) {
	                var filter = /^([0-9]{3,4}-)?[0-9]{7,8}$/;
	                return filter.test($.trim(_MPhoneNumber));
	            },
	            //检查邮箱格式
	            CheckMail: function (_EMail) {
	                var filter = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
	                return filter.test($.trim(_EMail));
	            },
	            //检查半角英数字
	            CheckString: function (_String) {
	                var filter = /^[\w]+$/;
	                return filter.test($.trim(_String));
	            },
	            //判断正数
	            CheckPNumber: function (_Number) {
	                var reg = /^\d+(?=\.{0,1}\d+$|$)/
	                if (reg.test($.trim(_Number))) {
	                    return true;
	                }
	                return false;
	            },
	            //判断正数
	            CheckNumber: function (_Number) {
	                var reg = /^\\d+$/;
	                if (reg.test($.trim(_Number))) {
	                    return true;
	                }
	                return false;
	            },
	            //检查正整数
	            CheckInt: function (_String) {
	                var filter = /^[0-9]*[1-9][0-9]*$/;
	                return filter.test($.trim(_String));
	            },
	            //检查数字
	            CheckNumberInt: function (_String) {
	                var filter = /^[0-9]*$/;
	                return filter.test($.trim(_String));
	            },
	            //检查证密码用(6～20位字母数字组合)
	            CheckPassWord: function (_String) {
	                var filter = /^(?=.*[0-9])(?=.*[a-zA-Z])([a-zA-Z0-9]{6,20})$/;
	                return filter.test($.trim(_String));
	            },
	            //检查decimal(8,2)
	            CheckDecimal: function (_String) {
	                var filter = /^(?!.{12,}$)\d+(\.\d{1,2})?$/;
	                return filter.test($.trim(_String));
	            },
	 
	            //检查HTML和JS脚本进行
	            CheckHTML: function (_String) {
	                var filter = RegExp("[<>]");
	                return filter.test(_String);
	            },
	 
	            //JS 脚本的检查 转化为转义字符 防止JS 攻击
	            CheckReplace: function (_String) {
	                return _String.replace(/[<>&"]/g, function (c) { return { '<': '<', '>': '>', '&': '&', '"': '"' }[c]; });
	            },
	 
	            //JS 转化 HTML 防止JavaScript  脚本的攻击
	            CheckReplaceHtml: function (_String) {
	                var arrEntities = { 'lt': '<', 'gt': '>', 'nbsp': ' ', 'amp': '&', 'quot': '"' };
	                return _String.replace(/&(lt|gt|nbsp|amp|quot);/ig, function (all, t) { return arrEntities[t]; });
	            },
	 
	            //检查输入的特殊的字符
	            SpecialChar: function (_String) {
	                var Pattern = new RegExp("[`~!@#$^&*()=|{}':;',\\[\\].<>/?~！@#￥……&*（）——|{}【】‘；：”“'。，、？]");
	                //关于特殊的字符的验证
	                if (Pattern.test($.trim(_String))) {
	                    return false;
	                }
	                return true;
	            },
	 
	            //IP地址的验证
	            IPAddressUrl: function (_String) {
	                var Pattern = /(http|ftp|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?/;
	                if (Pattern.test($.trim(_String))) {
	                    return false;
	                }
	                return true;
	            },
	            //检查移动客户端
	            CheckMobile: function () {
	                var sUserAgent = navigator.userAgent.toLowerCase();
	                var bIsIpad = sUserAgent.match(/ipad/i) == "ipad";
	                var bIsIphoneOs = sUserAgent.match(/iphone os/i) == "iphone os";
	                var bIsMidp = sUserAgent.match(/midp/i) == "midp";
	                var bIsUc7 = sUserAgent.match(/rv:1.2.3.4/i) == "rv:1.2.3.4";
	                var bIsUc = sUserAgent.match(/ucweb/i) == "ucweb";
	                var bIsAndroid = sUserAgent.match(/android/i) == "android";
	                var bIsCE = sUserAgent.match(/windows ce/i) == "windows ce";
	                var bIsWM = sUserAgent.match(/windows mobile/i) == "windows mobile";
	                if (bIsIpad || bIsIphoneOs || bIsMidp || bIsUc7 || bIsUc || bIsAndroid || bIsCE || bIsWM) {
	                    return true;
	                }
	                else {
	                    return false;
	                }
	            },
	 
	            // 检查 SQL 注入 URL
	            CheckSqlUrl: function (_String) {
	                var sUrl = location.search.toLowerCase();
	                var sQuery = sUrl.substring(sUrl.indexOf("=") + 1);
	                re = /select|update|delete|truncate|join|union|exec|insert|drop|count|'|"|;|>|<|%/i;
	                if (re.test(sQuery)) {
	                    return true;
	                }
	                return false;
	            },
	 
	            //检查SQL 普通输入的注入
	            CheckSqlForm: function (_String) {
	                re = /select|update|delete|exec|count|'|"|=|;|>|<|%/i;
	                if (re.test(_String.value)) {
	                    _String.value = "";
	                    _String.className = "errInfo";
	                    _String.focus();
	                    return false;
	                }
	                return true;
	            },
	 
	        },
	}
})
