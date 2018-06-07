#![feature(type_ascription)]
use time::*;

use rustc_serialize::hex::ToHex;
use rustc_serialize::base64:: {ToBase64, STANDARD};
 
pub mod vaptchaconfig;
pub mod hmac_sha1;



pub struct Vaptcha{
    _publickey : String,
    _lastCheckDownTime : i64,
    _isDown : bool,
    _id : String,
    _key : String,
    _passedSignatures : Vec<String>,
}


impl Vaptcha{
   pub fn new(id : String, key : String)->Vaptcha{
         Vaptcha{
             _id :id,
             _key : key,
             _passedSignatures : vec![],
             _publickey : "".to_string(),
             _isDown : false, 
             _lastCheckDownTime : 0,
         }
    } 
    pub fn get_challenge(&mut self, sceneid : String) -> String{
        let url : String = format!("{}{}", vaptchaconfig::api_url , vaptchaconfig::get_canllenge_url);
        let now : i64 = get_unixtime_milliseconds();
        let id = self._id.clone();
        let key = self._key.clone();
        let query = format!("id={}&scene={}&time={}&version={}&sdklang={}", id, sceneid, now, vaptchaconfig::version, vaptchaconfig::sdklang);
        let q1=query.clone();
        let signature : String = hmacsha1(key, query);
        if !self._isDown{
            let challenge = http_get(format!("{}?{}&signature={}", url.as_str(), q1.as_str(), signature.as_str()).as_str());
            if challenge == vaptchaconfig::request_usedup {
                self._lastCheckDownTime = now;
                self._isDown=true;
                self._passedSignatures = vec![];
                return get_downtime_captcha(self);
            }
            if challenge.is_empty() {
                if get_down_state() {
                     self._lastCheckDownTime = now;
                self._isDown=true;
                self._passedSignatures = vec![];
                }
                return get_downtime_captcha(self);
            } 
            return format!("{}{}{}", "{",format!("\"id\":\"{}\",\"challenge\":\"{}\"", self._id, challenge.as_str()) , "}");
        } 
        if now - self._lastCheckDownTime > vaptchaconfig::down_check_time{
                self._lastCheckDownTime = now;
                let challenge = http_get(format!("{}?{}&signature={}", url.as_str(), q1.as_str(), signature.as_str()).as_str());
                if !challenge.is_empty() && challenge != vaptchaconfig::request_usedup{
                    self._isDown = false;
                    self._passedSignatures=vec![];
 
                    return format!("{}{}{}", "{",format!("\"id\":\"{}\",\"challenge\":\"{}\"", self._id.as_str(), challenge.as_str()).as_str() , "}"); 
                } 
        }    
        get_downtime_captcha(self)
    } 

    pub fn validate(&mut self, challenge : &str, token : String, sceneid : String) -> bool {
        if !self._isDown && !challenge.is_empty() {
            let _id = self._id.clone();
            let _key = self._key.clone();
            return normal_validate(_id, _key, challenge, token, sceneid);
        }
        downtime_validate(self, token)
    }

    pub fn downtime(&mut self, data : String) -> String{
         let key=self._key.clone();
        if data.is_empty(){
            return "{\"error\":\"parms error\"}".to_string();
        } 
        let datas : Vec<&str> = data.split(",").collect(); 
        return match datas[0] {
            "request" => get_downtime_captcha(self),
            "getsignature"  => 
                if datas.len() <2{ 
                    "{\"error\":\"parms error\"}".to_string() 
                }
                else{
                    let time : i64 = datas[1].parse::<i64>().unwrap();
                    get_signature(key, time)
                },
            "check" =>
                if datas.len() < 5{
                    return "{\"error\":\"parms error\"}".to_string();
                }
                else {
                    let time1 = datas[1].parse::<i64>().unwrap();
                    let time2 = datas[2].parse::<i64>().unwrap();
                    let signature = datas[3];
                    let captcha = datas[4];
                    downtime_check(key, time1, time2, signature.to_string(), captcha.to_string())
                },         
            _ => "{\"error\":\"parms error\"}".to_string()
        }
    } 
}


 fn get_unixtime_milliseconds()->i64{
        let clock= Timespec::new(0,0);
        let epoch = time::at_utc(clock);
        let now = time::now_utc(); 
        let ts = now - epoch;
        ts.num_milliseconds()
    }

    fn get_milliseconds(time : i64)->i64{
        let clock= Timespec::new(0, 0);
        let epoch = time::at_utc(clock); 
        let time_clock=Timespec::new(time, 0);
        let end = time::at_utc(time_clock);
        let ts = end - epoch;
        ts.num_milliseconds()
    }

    fn md5ecode(data : String) -> String{

        let digest = md5::compute(&data);
        let hash = format!("{:x}", digest);
        hash
    }

    fn hmacsha1(key: String, query : String)->String{
        let config = STANDARD; 
        hmac_sha1::hmac_sha1(key.as_bytes(), query.as_bytes())
        .to_base64(config)
        .replace("/","")
        .replace("=","")
        .replace("+","") 
    } 

    fn http_get(url : &str) -> String{
        let res = match get(url){
            Ok(mut ss) => ss.text().unwrap(),
            Err(_) => "".to_string()
        };
        res
    }

    fn get(url : &str) -> Result<reqwest::Response, reqwest::Error>{
        let mut body  = reqwest::get(url)?; 
        Ok(body)
    }
    fn http_post(url : &str, data: &str) -> String{
        let res = match post(url, data){
            Ok(mut ss) => ss.text().unwrap(),
            Err(_) => "".to_string()
        };
        res
    }
    fn post(url : &str, data: &str) -> Result<reqwest::Response, reqwest::Error>{  
        let client = reqwest::Client::new();
        let res = client.post(url)
        .json(&data)
        .send()?;
        Ok(res)
    }

      fn get_down_state() -> bool{
    http_get(vaptchaconfig::isdownpath) == "false"
    }

    fn get_PublicKey() ->String {
        http_get(vaptchaconfig::publickey_path)
    }

    fn get_signature(key : String, time : i64) -> String{
        let now : i64 =  get_unixtime_milliseconds();
        if now -time > vaptchaconfig::RequestAbateTime{
            return "".to_string();
        } 
        let signature : String = md5ecode(format!("{}{}", key, now)); 
            return format!("{}{}{}", "{", format!("\"time\":\"{}\",\"signature\":\"{}\"", now, signature), "}");   
    }
    fn downtime_check(key : String, time1 : i64, time2 : i64, signature : String, captcha : String) -> String{
        let now : i64 = get_unixtime_milliseconds(); 
        if now -time1 >vaptchaconfig::RequestAbateTime || signature != md5ecode(format!("{}{}", key, now)){
            
          return format!("{}{}{}", "{", format!("\"result\":\"{}\"", false), "}");  
        }
        if now -time2 < vaptchaconfig::ValidateWaitTime{
             return format!("{}{}{}", "{", format!("\"result\":\"{}\"", false), "}");  
        }
        let mut code =format!("{}{}",time1, key ); 
        let trueCaptcha : String = md5ecode(code);

        if  trueCaptcha == captcha.to_lowercase(){ 
            let token = format!("{},{}", now, md5ecode(format!("{}{}vaptcha", now, key)));  
            let data = format!("{}{}{}", "{", format!("\"result\":true,\"token\":\"{0}\"", token), "}");
            return data;
        }
        "{\"result\":false}".to_string()
    }
    fn normal_validate(_id : String, _key : String, challenge : &str, token : String, sceneid : String) -> bool{
         
        if token.is_empty() || challenge.is_empty() || token != md5ecode(format!("{}vaptcha{}", _key.as_str(), challenge)){
            return false;
        }
        let url = format!("{}{}", vaptchaconfig::api_url, vaptchaconfig::validate_url);
        let query : String = format!("id={}&scene={}&token={}&time={}&version={}&sdklang={}"
                    , _id.as_str(), sceneid.as_str(), token, get_unixtime_milliseconds(), vaptchaconfig::version, vaptchaconfig::sdklang);
        let query1 = query.clone();
        let signature : String = hmacsha1(_key, query1);
        http_post(&url, format!("{}&signature={}", query, signature).as_str()) == "100".to_string()
    }

    fn downtime_validate(v : &mut Vaptcha, token : String) -> bool{
        if token.is_empty(){
            return false;
        }
        let strs : Vec<&str>= token.split(",").collect();
        if strs.len() < 2{
            return false;
        }
        let time : i64 = get_milliseconds(strs[0].parse::<i64>().unwrap());
        let signature : &str = strs[1];
        let now : i64 = get_unixtime_milliseconds();
        if(now -time) > vaptchaconfig::ValidatePassTime{
            return false;
        }
        let mut data =format!("{}{}vaptcha", time, v._key); 
        let signatureTrue : String = md5ecode(data);
        let mut res=false;
        if signatureTrue == signature{
           
            if v._passedSignatures.contains(&signature.to_string()){
                res = false;
            }
           
            v._passedSignatures.push(signature.to_string());
            if v._passedSignatures.len() >= vaptchaconfig::MaxLength{
               v._passedSignatures = v._passedSignatures[(v._passedSignatures.len() - vaptchaconfig::MaxLength +1)..].to_vec();
            }
            res = true;
        }
        res
    }
    fn get_downtime_captcha(v : &mut Vaptcha) -> String{
        let now =get_unixtime_milliseconds();
        let _md5 = md5ecode(format!("{}{}", now, v._key));
        let captcha :String = _md5[0..3].to_string();
        let verificationKey : String = _md5[30..].to_string();
        if v._publickey.is_empty(){
            v._publickey = get_PublicKey();
        }
        let url =format!("{}{}", md5ecode(format!("{}{}{}", captcha, verificationKey, v._publickey)), vaptchaconfig::pic_prefix) ;
        format!("{}{}{}", "{", format!("\"time\":\"{}\",\"url\":\"{}\"", now, url), "}")
    }