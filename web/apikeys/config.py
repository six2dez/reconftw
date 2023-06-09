from pathlib import Path
import yaml

params = {"censyssecret": ["censys", "secret"], "circlusername":["circl", "username"], "circlpassword":["circl", "password"], "digicertusername": ["certcentral", "username"], "facebooksecret":["facebook", "secret"], "fofausername": ["fofa", "username"], "rikiqusername":["passivetotal", "username"], "spamhaususername":["spamhaus", "username"], "spamhauspassword":["spamhaus", "password"], "twittersecret":["twitter", "secret"], "zoomeyeusername":["zoomeye", "username"], "zoomeyepassword":["zoomeye", "password"], "yandexusername":["yandex", "username"]}

def ReconConfig(name, key=None, get=None):
    name = name.replace("_", "").lower()

    names = {
        "shodan":"SHODAN_API_KEY",
        "whoisxml":"WHOISXML_API",
        "xssserver":"XSS_SERVER",
        "collabserver":"COLLAB_SERVER",
        "slackchanel":"slack_channel",
        "slackauth":"slack_auth",
    }


    if name in names:
        name = names[name]
        file = "../reconftw.cfg"

        lines = open(file, "r").readlines()

        subs = {}

        if key != None:
            for line in lines:
                if name in line and key != "":
                    subs[line] = name+'="'+key+'"\n'
            
                    break
                elif name in line and key == "":
                    subs[line] = '#'+name+'="XXXXXXXXXXXXX"\n'
                    break

            for sub in subs:
                replace = Path(file)
                replace.write_text(replace.read_text().replace(sub, subs[sub], 1))

        elif get == True:
            result = ""
            for line in lines:
                if name in line:
                    result = line.split("=")[1].replace(" ", "")
                    break

            if "XXXXXXXX" in result or "XXX-XXX-XXX" in result:
                return ""
            else:
                return result.replace('"', '')


#https://ddaniboy.github.io/sariel.html
def amassConfig(name, key=None, get=None):
    file = str(Path.home())+"/.config/amass/config.ini"
    name = name.lower()

    lines = open(file, "r").readlines()

    if name in params:
        param = params[name][1]
        name = params[name][0]
    else:
        param = "apikey"


    conf = []
    cont = False

    sub = ""
    apikey = ""

    for line in lines:

        if "data_sources."+name in line.lower():
            cont = True

        if cont == True:
            conf.append(line)
            sub += line
            if param in line:
                cont = False
                
                if len(line.split("=")) > 1:
                    apikey = line.split("=")[1].replace("\n", "")
                else:
                    apikey = ""
                break
    
    

    if get == True:
        return apikey.replace(" ", "")
    else:
        apikey = apikey.replace(" ", "")
        key = key.replace(" ", "")
        if apikey != key and key != "":
            final = ""
            for con in conf:
                if con != "":
                    if con[0] == "#":
                        con = con.replace("#", "", 1)
                    while con[0] == " ":
                        con = con.replace(" ", "", 1)

                if param in con.lower():
                    con = param + " = "+key+"\n"

                
                final += con

            replace = Path(file)
            replace.write_text(replace.read_text().replace(sub, final, 1))



        elif apikey != "" and key == "":
            final = ""
            for con in conf:
                if con != "":
                    con = "#"+con
                if param in con.lower():
                    con = "#"+param+" =\n"

                
                final += con

            
            replace = Path(file)
            replace.write_text(replace.read_text().replace(sub, final, 1))




def GithubConfig(number, key=None, get=None):
    file = str(Path.home())+"/Tools/.github_tokens"
    number = int(number)-1
    lines = open(file, "r").readlines()

    if len(lines) <= 5:

        lines = open(file, "w")
        for i in range(0, 6):
            lines.write("\n")
        lines.close()


    if key != None:
        if key != "":
            lines[number] = key+"\n"
        elif key == "" and lines[number] != key:
            lines[number] = "\n"

        gitTokens = open(file, "w")
        for item in lines:
            gitTokens.write(item)
        gitTokens.close()


    if get == True:

        lines = open(file, "r").readlines()

        result = lines[number]   

        return result
           
def theHarvesterConfig(name, key=None, get=None):
    namefile = str(Path.home())+"/Tools/theHarvester/api-keys.yaml"
    listOfNames = {"chaos":"projectDiscovery"}

    if name.lower() in listOfNames:
        name = listOfNames[name.lower()]

    if name == "censys":
        var = "secret"
    else:
        var = "key"


    with open(namefile) as file:
        if key != None:
            data = yaml.load(file, Loader=yaml.FullLoader)

            if key != data["apikeys"][name][var] and key != "":
                data["apikeys"][name][var] = key

            elif key == "" and data["apikeys"][name][var] != None:
                data["apikeys"][name][var] = None


            with open(namefile, "w") as comp:
                yaml.dump(data, comp)
        
        elif get == True:
            data = yaml.load(file, Loader=yaml.FullLoader)

            result = data["apikeys"][name][var]

            if result == None:
                return ''
            else:
                return result