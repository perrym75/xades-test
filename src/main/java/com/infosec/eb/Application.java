package com.infosec.eb;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.production.*;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.StringWriter;

public class Application {

    public static void main(String[] args) {
        try {
            KeyingDataProvider kp = new FileSystemKeyStoreKeyingDataProvider("jks",
                    "keys/keystore.jks",
                    certificates -> certificates.get(0),
                    () -> "password".toCharArray(),
                    (s, x509Certificate) -> "password".toCharArray(),
                    true);

            XadesSigningProfile p = new XadesTSigningProfile(kp);
            XadesSigner signer = p.newSigner();

            DataObjectDesc obj = new DataObjectReference("");
            SignedDataObjects dataObjs = new SignedDataObjects(obj).withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfOrigin());

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newDefaultInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new File("test.xml"));

            Element sigParentNode = doc.getDocumentElement();

            System.out.println(getStringFromDoc(doc));

            //new Enveloped(signer).sign(sigParentNode);
            signer.sign(dataObjs, sigParentNode);

            System.out.println(getStringFromDoc(doc));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String getStringFromDoc(org.w3c.dom.Document doc)    {
        try
        {
            DOMSource domSource = new DOMSource(doc);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
            writer.flush();
            return writer.toString();
        }
        catch(TransformerException ex)
        {
            ex.printStackTrace();
            return null;
        }
    }}
