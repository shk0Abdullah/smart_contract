from django.contrib.auth.decorators import login_required
import re 
from bson import ObjectId
from django.contrib import messages
import os
import json
from web3 import Web3
import subprocess
from solcx import set_solc_version
# Set the correct Solidity version
set_solc_version('0.8.28')
from django.core.files.storage import FileSystemStorage
from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from .models import SlitherReport, Buy, Contact
from django.contrib.auth import get_user_model
User = get_user_model()

def login_view(request):
    if request.method == "POST":

        username = request.POST["username"]
        password = request.POST["password"]
        print(username,password)
        user = authenticate(request, username=username, password=password)
        print(user)
        if user is not None:
            login(request, user)
            print('Logged in')
            return HttpResponseRedirect(reverse("audit"))
        else:
            return render(request, "login.html", {
                "messages": "Invalid username and/or password."
            })
    else:
        return render(request, "login.html")


def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse('index'))


def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]
        print(username, email)
        password = request.POST["password"]
        confirmation = request.POST["confirmation"]
        if password != confirmation:
            return render(request, "register.html", {
                "messages": "Passwords must match."
            })

        try:
            print('here')
            user = User.objects.create_user(username=username , email=email, password=password)
            print(user)
            print('Registered')
        except IntegrityError:
            return render(request, "register.html", {
                "messages": "Username already taken."
            })
        login(request, user)
        return (render(request,"login.html", {'messages': "Registered successfully!"}))
    else:
        return render(request, "register.html")


results = []
CONTRACTS_DIR = "contracts"
os.makedirs(CONTRACTS_DIR, exist_ok=True)

def index(request):
    return render(request, 'base.html')
@login_required
def myaudit(request):
    try:
        reports =SlitherReport.objects.filter(user_id= request.user.id)
        for report in reports:
            user_id = report.user_id
        username = User.objects.get(id=ObjectId(user_id))
        
        return render(request, 'myaudit.html',{'previous_audits': reports,'username':username})
    except:
        return render(request, 'myaudit.html')
@login_required
def view_report(request, filename):
    try:
        reports = SlitherReport.objects.filter(user_id= request.user.id, report_name= filename)
        for report in reports:
            report_data = report.report_data
        result, total = report_converter(report_data)
        return render(request, "analyzer.html", {"results": result, "total":total})
    except:
        pass
@login_required
def delete_report(request, filename):
    try:
        report = SlitherReport.objects.get(user_id= request.user.id, report_name= filename)
        report.delete()
        messages.success(request, True)
        return HttpResponseRedirect(reverse("myaudit"))
    except:
        pass
@login_required
def connector(request):
    return render(request, 'buy.html')

def settings_username(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]
        print(username,email)
        try:
            user = User.objects.get(id=request.user.id)
            user.username = username
            user.email = email
            user.save()
            messages.success(request, True)
            return HttpResponseRedirect(reverse("settings"))
        except IntegrityError:
            return render(request, "settings.html", {
                "messages": "Username already taken."
            })
    else:
        return render(request, "settings.html")
@login_required
def settings_password(request):
    if request.method == "POST":
        current_password = request.POST["current_password"]
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']
        if new_password != confirm_password:
            return render (request, 'settings.html',{'message':'Password not match'})
        else:
            user = User.objects.get(id=request.user.id)
            print(user.password)
            if user.check_password(current_password):
                user.set_password(new_password)                
                user.save()
            print(user.password)
            return render(request,'settings.html',{'message':'Success PAssword changed'})
    else:
        return render(request, "settings.html")

@login_required
def settings(request):
    return render(request, 'settings.html')
@login_required
def buy_callback(request):
    amount = request.GET.get('amount')
    tx_hash = request.GET.get('tx_hash')
    receipt_dict = json.loads(tx_hash)
    data = receipt_dict
    
    transaction_hash = str(data.get("transactionHash"))
    block_number = int(data.get("blockNumber"))
    from_address = str(data.get("from"))
    to_address = str(data.get("to"))
    event = data["events"][0].get("event")
    print(amount, event)

    Buy.objects.create(
        wallet_address = from_address,
        user = request.user,
        to_address = to_address,
        transaction_hash = transaction_hash,
        block_number = block_number,
        event_name = event,
        amount = amount
    )
    return render(request, 'buy.html', {'success': True, 'amount': amount, 'event': event})


address = "0x82DEdb6B7953cc3bB920CCbA0022c7E886761b05"
w3 = Web3(Web3.HTTPProvider("https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID"))
abi = '''[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"user","type":"address"},{"indexed":false,"internalType":"uint256","name":"credits","type":"uint256"}],"name":"CreditsConsumed","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"user","type":"address"},{"indexed":false,"internalType":"uint256","name":"credits","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"usdValue","type":"uint256"}],"name":"CreditsPurchased","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Withdrawn","type":"event"},{"inputs":[],"name":"CREDITS_PER_USD","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"MIN_USD","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"buyCredits","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"userAddress","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"consumeCredits","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"priceFeed","outputs":[{"internalType":"contract AggregatorV3Interface","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"userAddress","type":"address"}],"name":"showCredits","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"userCredits","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}]'''
abi = json.loads(abi)
contract = w3.eth.contract (address=address, abi=abi)    
def withdraw(request):
    from eth_account import Account
    try:
        private_key = "YOUR_RELAYER_PRIVATE_KEY"
        account = w3.eth.account.from_key(private_key)
        wallet_address = account.address

        contract_balance = w3.eth.get_balance(contract.address)
        if contract_balance == 0:
            return HttpResponse("Error: Contract has no ETH to withdraw", status=400)
            
        # Prepare transaction
        nonce = w3.eth.get_transaction_count(wallet_address)
        tx = contract.functions.withdraw().build_transaction({
            'from': wallet_address,
            'nonce': nonce,
            'gas': 150000, 
            'gasPrice': w3.to_wei('10', 'gwei'),
            'chainId': 11155111,  
        })
        
       
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
       
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
       
        if tx_receipt.status == 1:
            result = {
                "status": "success",
                "message": f"Withdrawn {w3.from_wei(contract_balance, 'ether')} ETH",
                "transaction_hash": w3.to_hex(tx_hash)
            }
            return HttpResponse(json.dumps(result), content_type="application/json")
        else:
            result = {
                "status": "failed",
                "message": "Transaction failed",
                "transaction_hash": w3.to_hex(tx_hash)
            }
            return HttpResponse(json.dumps(result), content_type="application/json", status=400)
        
    except Exception as e:
        return HttpResponse(f"Error: {str(e)}", status=500)



@login_required
def user(request):
    credits = 0
    data = None
    try:
        wallet_qs = Buy.objects.filter(user=request.user)
        if wallet_qs.exists():
            wallet = wallet_qs.first()  
            address_ = wallet.wallet_address
            credits = contract.functions.userCredits(address_).call()
            data = wallet_qs  
            return render(request, 'user.html', {
            'credits': credits,
            'data': data.first(),
            'datas':wallet_qs  
        })
        else:
            credits = 0
            data = None

    except Exception as e:
        print(f"Error in user view: {e}")  

    return render(request, 'user.html', {
        'credits': credits,
        'data': data  
    })

def doc(request):
    return render (request, "doc.html")
def contact(request):
    if request.method == "POST":
        try:
            email = request.POST.get('email','')
            message = request.POST.get('message','')
            Contact.objects.create(email=email, message= message).save()
            return render(request, 'base.html',{'message': 'success'})
        except: 
            return render(request, 'base.html', {'message': 'error'})
    return render(request, 'base.html')
@login_required
def audit(request):
    if request.method == "POST":
        print("I am In")
        uploaded_file = request.FILES.get("contract", None)
        if uploaded_file == None:
            return render(request, "analyzer.html", {"result": "No file uploaded"})
        contract_path = os.path.join(CONTRACTS_DIR, uploaded_file.name)

       
        fs = FileSystemStorage(location=CONTRACTS_DIR)
        fs.save(uploaded_file.name, uploaded_file)
        print("All is well")
        try:
            print("I am in try")
           
            result = subprocess.run(
                ["slither", contract_path], 
                capture_output=True, text=True
            )
            print(result)
            result = str(result)
            status = 'completed'
            print("After subprocess")
           

            try:
                report = SlitherReport(
                    user=request.user,
                    report_name=uploaded_file.name,
                    report_data=result, 
                    status=status
                )
                
                report.save()
                print(f"Successfully saved report. ID: {report.id}")
            except Exception as e:
                    print(f"Unexpected error: {str(e)}")

            print("After saving")
           
            results,total = report_converter(result)
            print(results, total)
            try:
                userAddress = Buy.objects.filter(user_id=request.user.id).first().wallet_address
                print(userAddress)
                from eth_account import Account
                private_key = "YOUR_RELAYER_PRIVATE_KEY"

                account = w3.eth.account.from_key(private_key)
                wallet_address = account.address

                contract_balance = w3.eth.get_balance(account.address)
                if contract_balance == 0:
                    return HttpResponse("Error: Contract has no ETH to withdraw", status=400)
                
              
                nonce = w3.eth.get_transaction_count(wallet_address)
                tx = contract.functions.consumeCredits(str(userAddress),200).build_transaction({
                'from': wallet_address,
                'nonce': nonce,
                'gas': 150000,  
                'gasPrice': w3.to_wei('10', 'gwei'),
                'chainId': 11155111,  
                })
                print('nnjk')
               
                signed_tx = w3.eth.account.sign_transaction(tx, private_key)
                tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                print(tx_hash)
                
                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                block_number = tx_receipt.blockNumber
                transaction_hash = tx_receipt.transactionHash.hex()
                
                print(transaction_hash)
                # print("logs: ",logs)
                Buy.objects.create(
                wallet_address = userAddress,
                user = request.user,
                to_address = address,
                transaction_hash = transaction_hash,
                block_number = block_number,
                event_name = 'CreditsConsumed',
            
                )
                os.remove(contract_path)
                return render(request, "analyzer.html", {"results": results, "total":total})
            except Exception as e:      
                print(str(e))      
                os.remove(contract_path)
                return render(request, "analyzer.html", {"results": results, "total":total})

        except Exception as e:
            return render(request, "analyzer.html", {"results": "Error: " + str(e)})
    print("I am out")
    return render(request, "audit.html")
def report_converter(result):
    results = str(result).replace("\\n", " ").replace("\\t", " ")  # Remove \n and \t
    results = re.sub(r"\s+", " ", results).strip()  
    pattern = r"INFO:Detectors:\s*(.*?)\s*Reference:\s*(.*?)\s*(?=INFO:Detectors:|INFO:Slither:)"
    results = re.findall(pattern, str(results), re.DOTALL)
            
    total = (len(results))
    return results,total

from django.http import JsonResponse
from langchain_huggingface import HuggingFaceEndpoint, ChatHuggingFace
# from langchain_community.llms import HuggingFaceEndpoint
from langchain_huggingface import HuggingFaceEmbeddings
from django.views.decorators.csrf import csrf_exempt
from langchain_community.document_loaders import TextLoader
from langchain_chroma import Chroma
from langchain.schema import Document
from langchain.text_splitter import CharacterTextSplitter 
from langchain.schema.output_parser import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate, PromptTemplate

@csrf_exempt
def chat(request):
    """Handles chat messages dynamically using AJAX."""

    if 'conversation' not in request.session:
        request.session['conversation'] = []

    if request.method == 'POST':
        query = request.POST.get('input_text', '').strip()

        if query.lower() == "clear":
            request.session['conversation'] = []
            request.session.modified = True
            return JsonResponse({'conversation': []})

        
        HF_token = os.environ.get('HF_token', 'YOUR_HUGGINNGFACE_INFERENCE_TOKEN')
        

        try:
            llm = HuggingFaceEndpoint(repo_id='mistralai/Mistral-7B-Instruct-v0.3', temperature=0.6, huggingfacehub_api_token=HF_token, timeout =500)
            model = ChatHuggingFace(llm=llm)
            reports = SlitherReport.objects.filter(user_id=request.user.id)

            documents = []
            for report in reports:
                report_text = f"{report.report_name}: {report.report_data}"
                documents.append(Document(page_content=report_text))

            text_splitter = CharacterTextSplitter(chunk_size=300, chunk_overlap=100)
            chunks = text_splitter.split_documents(documents)
            embeddings  = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
            persist_dir = 'chroma_db'
            vector_db = Chroma.from_documents(documents=chunks, embedding=embeddings,persist_directory=persist_dir)
            search = vector_db.similarity_search(query, k=3)
            prompt = 'Behave like a professional Assistant and did not mention Its worth nothing to go to the github repo Search for this User:{query} in {search}'
            prompt_template = ChatPromptTemplate.from_template(prompt)
            chain = prompt_template | model | StrOutputParser() 


            response = chain.invoke({'query':query, 'search':search})
            print(response)
            chat_entry = {'user': query, 'bot': response}
            request.session['conversation'].append(chat_entry)
            request.session.modified = True

        except Exception as e:
            response = "I didn't understand. Try again!"
            chat_entry = {'user': query, 'bot': response}
            request.session['conversation'].append(chat_entry)
            request.session.modified = True
            print(f"Error: {e}")

        return JsonResponse({'conversation': request.session['conversation']})

    return render(request, 'analyzer.html', {'conversation': request.session['conversation']})

