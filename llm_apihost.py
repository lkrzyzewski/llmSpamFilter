import os
import asyncio
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import torch
#from typing import List
import auth
import warnings
#import transformers
from transformers import AutoTokenizer, AutoModelForCausalLM
#from transformers.models.gemma3 import Gemma3ForCausalLM
import logging
from contextlib import asynccontextmanager

warnings.filterwarnings("ignore")

os.environ['CUDA_LAUNCH_BLOCKING'] = "1"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["SAFETENSORS_FAST_GPU"] = "1"
#os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "garbage_collection_threshold:0.6,max_split_size_mb:2048"

logfilename = "/var/log/gemma.log"
logging.basicConfig(filename=logfilename, filemode='a', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)


MAX_QUEUE_SIZE = 50

phishing_model = None
phishing_tokenizer = None
spam_model = None
spam_tokenizer = None
request_queue = None
device = None

phishing_model_foldername = "phishing folder name"
spam_model_foldername = "spam folder name"
#device = "cpu"


def define_device():
    """Determine and return the optimal PyTorch device based on availability."""

    print(f"PyTorch version: {torch.__version__}", end=" -- ")

    # Check if MPS (Metal Performance Shaders) is available for macOS
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        print("using MPS device on macOS")
        return torch.device("mps")

    # Check for CUDA availability
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"using {device}")
    return device



def prompt_phishing_template(data):
        return f"""
Analyze the subject and body of the email below.
Assess whether the email is a phishing scam and answer "phishing" or "ok"

Subject:
{data["subject"]}

Email Body:
{data["body"]}"""

def generate_phishing_prompt(data_point):
    messages = [
        {"role": "user", "content": prompt_phishing_template(data_point)}
    ]
    return messages

def prompt_spam_template(data):
        return f"""
Analyze the subject and body of the email below.
Assess whether the email is spam and answer "spam" if so or "ham" if not.

Subject:
{data["subject"]}

Email Body:
{data["body"]}"""

def generate_spam_prompt(data_point):
    messages = [
        {"role": "user", "content": prompt_spam_template(data_point)}
    ]
    return messages


async def process_queue(max_new_tokens=5, temperature=0.01):
    global phishing_model, phishing_tokenizer, spam_model, spam_tokenizer, request_queue, device
    log.info("Queue processing worker started.")
    while True:
        try:
            # Get a task from the queue (blocks if the queue is empty)
            item = await request_queue.get()
            phishing_prompt = item["phishing_prompt"]
            spam_prompt = item["spam_prompt"]
            future: asyncio.Future = item["future"]


            p_pred = "" # List to store predicted sentiment labels
            #model.eval() # Set model to evaluation mode
            phishing_tokenizer.padding_side = "left"
            phishing_input_ids = phishing_tokenizer.apply_chat_template(phishing_prompt, return_tensors="pt").to(device)
            
            spam_tokenizer.padding_side = "left"
            spam_input_ids = phishing_tokenizer.apply_chat_template(spam_prompt, return_tensors="pt").to(device)           
            # Generate output from the model
            with torch.no_grad(): # Disable gradient calculations for inference
                #Phishing pred
                phishing_outputs = phishing_model.generate(phishing_input_ids,
                                        #max_new_tokens=max_new_tokens,
                                        temperature=temperature,
                                        #pad_token_id=phishing_tokenizer.eos_token_id # Avoid warning
                                        )
                #Spam pred
                spam_outputs = spam_model.generate(spam_input_ids,
                                        #max_new_tokens=max_new_tokens,
                                        temperature=temperature,
                                        #pad_token_id=phishing_tokenizer.eos_token_id # Avoid warning
                                        )
                                
            if len(phishing_outputs) > 0:
                phishing_decoded_text = phishing_tokenizer.decode(phishing_outputs[0], skip_special_tokens=True)
                try:
                    phishing_generated_text = phishing_decoded_text.split("assistant")[-1].strip()
                except IndexError:
                    phishing_generated_text = "" # Handle cases where the marker isn't found
                    log.info("Failed to generate phishing tokens")
                finally:
                    # Clearing GPU memory (may help in some cases)
                    del phishing_prompt
                    del phishing_outputs
                    del phishing_input_ids
            if len(spam_outputs) > 0:
                spam_decoded_text = spam_tokenizer.decode(spam_outputs[0], skip_special_tokens=True)
                try:
                    spam_generated_text = spam_decoded_text.split("assistant")[-1].strip()
                except IndexError:
                    spam_generated_text = ""
                    log.info("Failed to generate spam tokens")
                finally:
                    del spam_prompt
                    del spam_outputs
                    del spam_input_ids
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
            log.info(f"Generated tokens: Phishing: {phishing_generated_text} Spam: {spam_generated_text}")

            if "phishing" in phishing_generated_text:
                p_pred = "phishing"
            elif "ok" in phishing_generated_text:
                p_pred = "ok"
            else:
                # Fallback if no clear label is found in the short generation
                p_pred = "none"
                # print(f"Warning: Could not parse sentiment from: '{generated_text}' derived from '{full_decoded_text}'")
            if "spam" in spam_generated_text:
                s_pred = "spam"
            elif "ham" in spam_generated_text:
                s_pred = "ham"
            else:
                s_pred = "none"

            future.set_result({"phishing_pred": p_pred, "spam_pred": s_pred})
        
        except asyncio.CancelledError:
            log.info("Queue processing worker stopped.")
            break # Exit the loop if the task was canceled
        except Exception as e:
            log.error(f"Unexpected error in the queue worker: {e}", exc_info=True)
            # If an item was retrieved, but an error occurred before setting the future
            if 'future' in locals() and future and not future.done():
                try:
                    future.set_exception(e)
                except asyncio.InvalidStateError:
                     # The future might have already been set or canceled in the meantime
                     log.warning("Cannot set exception on Future - it has likely already completed.")
            # A short pause to avoid a potential error loop
            await asyncio.sleep(1)
        finally:
            # Mark the task as done in the asyncio queue
            if 'request_queue' in globals() and request_queue:
                 try:
                    request_queue.task_done()
                 except ValueError:
                    # This can happen if task_done() is called more times than put()
                    log.warning("Attempted to call task_done() on an empty queue or an already completed task.")


class PredData(BaseModel):
    subject: str
    body: str



@asynccontextmanager
async def lifespan(app: FastAPI):
    global phishing_model, phishing_tokenizer, spam_model, spam_tokenizer, request_queue, device, worker_task
    
    compute_dtype = torch.float16
    device = define_device()

    try:
        #Phishing classification model
        phishing_model = AutoModelForCausalLM.from_pretrained(
            f"./{phishing_model_foldername}",
            torch_dtype=compute_dtype,
            #attn_implementation="eager", # Specify attention implementation
            #low_cpu_mem_usage=True,      # Reduces CPU RAM usage during loading
            device_map=device,            # Automatically map model layers to the device
        )
        # Define maximum sequence length for the tokenizer
        #max_seq_length = 8192 # Gemma 3 supports long contexts
        # Load the tokenizer
        phishing_tokenizer = AutoTokenizer.from_pretrained(
            f"./{phishing_model_foldername}",
            padding_side = "left",
            #max_seq_length=max_seq_length,
            device_map=device # Map tokenizer operations if relevant (less common)
        )
        phishing_model.eval()
        
        #Spam classification model
        spam_model = AutoModelForCausalLM.from_pretrained(
            f"./{spam_model_foldername}",
            torch_dtype=compute_dtype,
            #attn_implementation="eager", # Specify attention implementation
            #low_cpu_mem_usage=True,      # Reduces CPU RAM usage during loading
            device_map=device,            # Automatically map model layers to the device
        )
        # Define maximum sequence length for the tokenizer
        #max_seq_length = 8192 # Gemma 3 supports long contexts
        # Load the tokenizer
        spam_tokenizer = AutoTokenizer.from_pretrained(
            f"./{spam_model_foldername}",
            padding_side = "left",
            #max_seq_length=max_seq_length,
            device_map=device # Map tokenizer operations if relevant (less common)
        )
        spam_model.eval()
        
        # Initializing asyncio queue
        request_queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
        log.info(f"Request queue initialized (max size: {MAX_QUEUE_SIZE}).")
        
        # Starting the queue processing worker in the background
        worker_task = asyncio.create_task(process_queue())
        log.info("The queue processing worker has been started in the background.")
        
    except Exception as e:
        log.error(f"Critical error during model or worker initialization: {e}", exc_info=True)
        # Application closing or notification logic can be added here
        raise RuntimeError(f"Failed to initialize the application: {e}") from e
    
    yield # Application is running

    # Code executed on application shutdown
    log.info("Closing the application...")
    if worker_task:
        log.info("Canceling the queue worker task...")
        worker_task.cancel()
        try:
            await worker_task # Wait for the worker to finish
            log.info("Queue worker task finished.")
        except asyncio.CancelledError:
            log.info("The queue worker task was canceled correctly.")
        except Exception as e:
            log.error(f"Error while waiting for the worker to finish: {e}", exc_info=True)
    
    log.info("Releasing resources...")
    del phishing_model
    del phishing_tokenizer
    del spam_model
    del spam_tokenizer
    if torch.cuda.is_available():
        torch.cuda.empty_cache()


app = FastAPI(dependencies=[Depends(auth.validate_api_key)], lifespan=lifespan)

@app.post("/")
async def process_data(data: PredData):
    
    # Store the EOS token for later use in prompts
    #EOS_TOKEN = tokenizer.eos_token
    Subject = data.subject
    body = data.body
    
    #prompt = generate_test_prompt(Subject, body)
    
    #pred = predict(prompt, model, tokenizer, define_device())
    #print(pred)
    """
    Accepts input data, adds the request to the queue, and waits for the result from the Gemma model.
    """
    global request_queue
    if not request_queue:
         raise HTTPException(status_code=503, detail="Server is not ready (queue not initialized).")

    if request_queue.full():
        log.warning("The request queue is full. Rejecting request.")
        raise HTTPException(status_code=503, detail="The server is overloaded, please try again later.")

    # Create a Future that will signal the completion of processing for this specific request
    future = asyncio.Future()

    # Add data and the Future to the queue
    try:
        phishing_prompt = generate_phishing_prompt({"subject": Subject, "body": body})
        spam__prompt = generate_spam_prompt({"subject": Subject, "body": body})
        await request_queue.put({"phishing_prompt": phishing_prompt, "spam_prompt": spam__prompt,"future": future})
        log.info(f"Added task to the queue. Current queue size: {request_queue.qsize()}")
    except Exception as e:
        log.error(f"Error while adding task to the queue: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error while queueing the task.")

    # Wait for the processing result (set by the background worker)
    try:
        # A timeout can be added, e.g., asyncio.wait_for(future, timeout=60.0)
        result = await future
        return result
    except asyncio.TimeoutError:
         log.error("Timeout exceeded while waiting for a response from the model.")
         raise HTTPException(status_code=504, detail="Request processing time limit exceeded.")
    except Exception as e:
        log.error(f"Error returned by the processing worker: {e}", exc_info=True)
        # Return a more generic error to the user
        raise HTTPException(status_code=500, detail=f"Error during request processing: {type(e).__name__}")

@app.get("/health")
async def health_check():
    """A simple endpoint for checking the service status."""
    # More advanced checks can be added, e.g., whether the model is loaded
    return {"status": "ok", "queue_size": request_queue.qsize() if request_queue else "N/A"}
