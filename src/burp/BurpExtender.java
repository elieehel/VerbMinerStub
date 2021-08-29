package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;


public class BurpExtender implements IBurpExtender, IHttpListener {
	private static String verbs[] = new String[] {"OPTIONS", "GET", "POST"};
	private IExtensionHelpers helpers;
	private IBurpExtenderCallbacks callbacks;
	private PrintWriter stdout;
	private ArrayList<String> history = new ArrayList<>();
	private Object lock = new Object();
	public static void main(String[] args) {}
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		
		callbacks.setExtensionName("VerbMinerStub");

		stdout = new PrintWriter(callbacks.getStdout(), true);
	    stdout.print("Initializing VerbMinerStub\n");
	    stdout.flush();
		
		callbacks.registerHttpListener(this);

        helpers = callbacks.getHelpers();
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest) {
			return;
		}
		if (stdout.checkError()) {
			stdout.print("We had a printing error ... :(");
			stdout.flush();
		}
		IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
		boolean inScope = callbacks.isInScope(requestInfo.getUrl());
		if (!inScope || history.contains(requestInfo.getUrl().toString())) 
			return;
		synchronized (this.lock) { 
			String method = requestInfo.getMethod();
			byte space = " ".getBytes()[0];
			byte[] byteRequest = messageInfo.getRequest();
			int endOffset = 3;
			
			// Find end of verb offset in request
			for (; endOffset < messageInfo.getRequest().length; endOffset++) {
				if (byteRequest[endOffset] == space) {
					break;
				}
			}

			for (int b = 0; b < verbs.length; b++) {
				String verb = verbs[b];
				if (!method.equals(verb)) {
					byte[] newReq = Arrays.copyOf(verb.getBytes(), verb.getBytes().length + byteRequest.length - endOffset);
					System.arraycopy(byteRequest, endOffset, newReq, verb.length(), byteRequest.length - endOffset);
					new Thread(new ThreadedRequest(messageInfo.getHttpService(), newReq)).start();
				}
			}
			history.add(requestInfo.getUrl().toString());
		}
	}
	
	private class ThreadedRequest implements Runnable {
		private byte[] request;
		private IHttpService httpService;
		public ThreadedRequest(IHttpService httpService, byte[] request) {
			this.request = request;
			this.httpService = httpService;
		}
		public void run() {
			IHttpRequestResponse response = callbacks.makeHttpRequest(this.httpService, this.request);
			
			IRequestInfo req = helpers.analyzeRequest(response);
			IResponseInfo res = helpers.analyzeResponse(response.getResponse());
			
			stdout.write("Response for verb " + req.getMethod() +  " " + req.getUrl().getHost() + req.getUrl().getFile() + " > Status code: " + res.getStatusCode() + ", size " + response.getResponse().length + " b\n");
			stdout.flush();
		}
	}
}
