from .log import logger
from .config import config

logger = logger.getChild("pac")

def generate_pac():
    pacfile = """class TrieNode {
    constructor(value){
        this.value = value;
        this.num=1;
        this.deep=0;
        this.son=[];
        this.isEnd=false;
    }
    findNode(value){
        for(let i=0;i<this.son.length;i++){
            const node=this.son[i]
            if(node.value == value){
                return node;
            }
        }
        return null;
    }
}
class Trie {
    constructor(){
        this.root=new TrieNode(null);
        this.size=1;
    }
    insert(str){
        let node=this.root;
        for(let c of str){
            let snode = node.findNode(c);
            if(snode==null){
                snode=new TrieNode(c)
                snode.deep=node.deep+1;
                node.son.push(snode);
            }else{
                snode.num++;
            }
            node=snode;
 
        }
        
        if (!node.isEnd) {
            this.size++;
            node.isEnd = true;
        }
    }
    has(str){
        let node=this.root;
        for(let c of str){
            const snode=node.findNode(c)
            if(snode){
                node=snode;
            }else{
                return false;
            }
        }
        return node.isEnd;
    }
}

let tr=null;
function BuildAutomatom(arr) {
    
    tr=new Trie()
    arr.forEach(function (item) {
        tr.insert(item)
    })
    
    root=tr.root;
    root.fail=null;
    const queue=[root]
    let i=0;
    while(i<queue.length){
        const temp=queue[i];
        for(let j=0;j<temp.son.length;j++){
            const node=temp.son[j]
            if(temp===root){
                node.fail=root;
            }else{
                node.fail=temp.fail.findNode(node.value)||root;
            }
            queue.push(node);
        }
        i++
    }
}

function MatchAutomatom(str) {
    let node=tr.root;
    const data=[];
    for(let i=0;i<str.length;i++){
 
        let cnode=node.findNode(str[i])
        while(!cnode&&node!==tr.root){
            node=node.fail;
 
            cnode=node.findNode(str[i])
        }
        if(cnode){
            node=cnode;
        }
        if(node.isEnd){
            data.push({
                start:i+1-node.deep,
                len:node.deep,
                str:str.substr(i+1-node.deep,node.deep),
                num:node.num,
            })
        }
    }
    return data;
}

let domains="""

    with open("config_pac.json") as f:
        pacfile+=f.read()
    pacfile += ';\n'
    
    proxy_url='"'
    if config["pac_proxy"]=="HTTP":
        proxy_url+=f"PROXY 127.0.0.1:{config['port']}"
    elif config["pac_proxy"]=="SOCKS5":
        proxy_url+=f"SOCKS5 127.0.0.1:{config['port']}"
    else:
        raise ValueError("Invalid pac_proxy value")
    proxy_url+='";'

    pacfile += "BuildAutomatom(domains);\n"
    pacfile += """function FindProxyForURL(url, host) {
    if(MatchAutomatom("^"+host+"$").length)
         return """
    if config["pac_target"] == "DIRECT":
        pacfile += '"DIRECT";'
    elif config["pac_target"] == "PROXY":
        pacfile += proxy_url
    else:
        raise ValueError("Invalid pac_target value")
    
    pacfile += """
    else
        return """
    if config["pac_default"] == "DIRECT":
        pacfile += '"DIRECT";'
    elif config["pac_default"] == "PROXY":
        pacfile += proxy_url
    else:
        raise ValueError("Invalid pac_default value")
    pacfile += '\n}'

    with open("PAC_cache.pac", "w") as f:
        f.write(pacfile)

def load_pac():
    with open("PAC_cache.pac", "r") as f:
        pacfile = f.read()
    return f"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {len(pacfile)}\r\n\r\n{pacfile}"