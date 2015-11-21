real_eval = eval;
var codeBlocks = new Array();
function eval(arg) {
    try 
    { 
        if(codeBlocks.indexOf(arg) == -1)
        {
            codeBlocks.push(arg)
                print(arg); 
            real_eval(arg);
        }
    } 
    catch (e) 
    { 
        print("eval() exception: " + e.toString());
    };
}

function alert(s) {
    print("ALERT");
    print(s);
}


function Element(s) {
    this.children = new Array();
    this.ElementName = s
        // return new String(s);
        this.setAttribute=function(o, v)
        {
            this.o = v;
            this.name = this.name + " " + o + "=" + v;
        }
    this.style = new object();
    this.appendChild=function(s)
    {
        e = new Element(s);
        this.children.push(e);
    }

    this.print=function()
    {
        print('<' + this.ElementName + '>');
        for (i in this.children) {
            this.children[i].print();
        }
    }
}

// declare a globally-accessible document object
function my_document () {
    this.elements = new Array();
    this.m_property="";
    this.cookie="";
    this.referrer = '';
    this.write=function(s)
    {
        print(s);
    }
    this.writeln=function(s)
    {
        print(s);
    }
    this.createElement=function(s)
    {
        // print("createElement " + s.toString());
        this.elements[s] = new Element(s);
        this.elements[s].print();
        return new Element(s);
    }
    this.getElementById=function(s)
    {
        print("getElementById " + s.toString());
        // return new Element(s);
        return this.elements[s];
    }
};
var document=new my_document();

function new_location(prop, oldv, newv) {
    print("document.write(\"<a href=" + newv + ">" + newv + "</a>\");");
}
function my_location() {
    this.href='';
    this.watch('href', new_location);
    this.reload = function() {
        return;
    }
}
var location = new my_location();
document.location = location;
document.watch('location', new_location)

function object() {
    this.history = '';
    this.document = new my_document();
    this.navigator = function(x) 
    {
        this.userAgent = '';
        this.appVersion = '';
        this.platform = 'Win32';
    }
    this.open=function(url) { return; }
}

var window = new object();
window.navigator.userAgent = '';
window.navigator.appVersion = '';
window.navigator.platform = 'Win32';
window.RegExp = RegExp;
window.parseInt = parseInt;
window.String = String;
window.location = '';
var navigator = window.navigator;
var self = new object();
var productVersion = '';
navigator.appName="Microsoft Internet Explorer"
navigator.appVersion="4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
navigator.userAgent="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
navigator.userLanguage = 'en-us';
var self = new object();
var productVersion = '';
var clientInformation = new object()
    clientInformation.appMinorVersion='';

    function ClientCaps () {
        this.isComponentInstalled=function(arg0, arg1) {
            return(false);
        }
        this.getComponentVersion=function(arg0, arg1) {
            return(NULL);
        }
    }

var top = new object();
top.document = document;

function setTimeout(todo, when) {
    // print ('setTimeout - ' + todo + ', ' + when);
    return(eval(todo));
}
window.setTimeout = setTimeout
