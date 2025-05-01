from langchain_huggingface import HuggingFaceEndpoint
from solcx import set_solc_version
# Set the correct Solidity version
set_solc_version('0.8.28')
import os
from django.http import HttpResponseRedirect
from django.shortcuts import render
from .models import User
from django.db import IntegrityError
from django.urls import reverse
import re
import subprocess
from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
from django.contrib.auth import authenticate, login, logout

results = []
YOUR_HFTOKEN = ''
def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse("index"))


def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]

        # Ensure password matches confirmation
        password = request.POST["password"]
        confirmation = request.POST["confirmation"]
        if password != confirmation:
            return render(request, "account/signup.html", {
                "messages": "Passwords must match."
            })

        # Attempt to create new user
        try:
            user = User.objects.create_user(username, email, password)
            user.save()
        except IntegrityError:
            return render(request, "account/signup.html", {
                "messages": "Username already taken."
            })
        login(request, user)
        return HttpResponseRedirect(reverse("audit"))
    else:
        return render(request, "account/signup.html")
def login_view(request):
    if request.method == "POST":

        # Attempt to sign user in
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)

        # Check if authentication successful
        if user is not None:
            login(request, user)
            return HttpResponseRedirect(reverse("audit"))
        else:
            return render(request, "account/login.html", {
                "messages": "Invalid username and/or password."
            })
    else:
        return render(request, "account/login.html")

# Directory to store Solidity files
CONTRACTS_DIR = "contracts"
os.makedirs(CONTRACTS_DIR, exist_ok=True)

# def signup(request):
#     return render(request, 'signup.html')
# def login(request):
#     return render(request, 'login.html')


def index(request):
    return render(request, 'base.html')

def audit(request):
    if request.method == "POST":
        print("I am In")
        uploaded_file = request.FILES.get("contract", None)
        if uploaded_file == None:
            return render(request, "analyzer.html", {"result": "No file uploaded"})
        contract_path = os.path.join(CONTRACTS_DIR, uploaded_file.name)

        # Save the file in /contracts/
        fs = FileSystemStorage(location=CONTRACTS_DIR)
        fs.save(uploaded_file.name, uploaded_file)
        print("All is well")
        try:
            # Run Slither analysis
            result = subprocess.run(
                ["slither", contract_path], 
                capture_output=True, text=True
            )
            print("subprocess run",result)
            
            # Regular expression to extract each detector block
            results = str(result).replace("\\n", " ").replace("\\t", " ")  # Remove \n and \t
            results = re.sub(r"\s+", " ", results).strip()  
            pattern = r"INFO:Detectors:\s*(.*?)\s*Reference:\s*(.*?)\s*(?=INFO:Detectors:|INFO:Slither:)"
            results = re.findall(pattern, str(results), re.DOTALL)
            print(results)
     
            total = (len(results))
            # print(cleaned_data)
            os.remove(contract_path)
            return render(request, "analyzer.html", {"results": results, "total":total})

        except Exception as e:
            return render(request, "analyzer.html", {"results": "Error: " + str(e)})
    print("I am out")
    return render(request, "audit.html")


from django.http import JsonResponse

from langchain.llms import HuggingFaceEndpoint
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def chat(request):
    """Handles chat messages dynamically using AJAX."""

    # Initialize chat session if not exists
    if 'conversation' not in request.session:
        request.session['conversation'] = []

    if request.method == 'POST':
        query = request.POST.get('input_text', '').strip()

        # If user types "clear", reset the chat
        if query.lower() == "clear":
            request.session['conversation'] = []
            request.session.modified = True
            return JsonResponse({'conversation': []})

        # Hugging Face API Token (Use secure storage in production)
        HF_token = os.environ.get('HF_token', YOUR_HFTOKEN)  # Replace with actual token
        repo_id = 'mistralai/Mistral-7B-Instruct-v0.3'

        try:
            llm = HuggingFaceEndpoint(repo_id=repo_id, temperature=0.6, huggingfacehub_api_token=HF_token)
            response = llm.invoke(f"Answer this query: {query} according to the slither results: {results}")

            # Store chat history
            chat_entry = {'user': query, 'bot': response}
            request.session['conversation'].append(chat_entry)
            request.session.modified = True

        except Exception:
            response = "I didn't understand. Try again!"
            chat_entry = {'user': query, 'bot': response}
            request.session['conversation'].append(chat_entry)
            request.session.modified = True

        # Return JSON response for AJAX
        return JsonResponse({'conversation': request.session['conversation']})

    # Render the full page if it's a normal request (not AJAX)
    return render(request, 'analyzer.html', {'conversation': request.session['conversation']})
