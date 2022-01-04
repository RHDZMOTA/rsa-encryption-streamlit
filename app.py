import json
import textwrap
import logging
from typing import Optional, Dict

from utils import RSAEncryption, KeyWrapper, rsa_encrypt, rsa_decrypt

import streamlit as st


logger = logging.getLogger(__name__)


def sidebar() -> str:
    option = st.sidebar.radio(
        label="Menu",
        options=[
            "Decrypt",
            "Encrypt",
            "Create Keys",
        ],
    )
    return option


def create_keys():
    markdown_content = textwrap.dedent(
        """
        ----
        
        **{key_type}**: {message}
        
        JSON Key:
        ```json
        {json_content}
        ```
        
        Hex. Alternative:
        ```text
        {hex_alternative}
        ```
        
        """
    )
    st.title("Create RSA Keys")
    with st.form("create-keys-forms"):
        nbits = int(st.text_input(label="[Required] nbits", value="1024") or 0)
        kwargs = json.loads(st.text_input(label="[Optional] kwargs", value="{}") or "{}")
        submitted = st.form_submit_button("Generate")
    if not submitted:
        return
    if nbits <= 0:
        st.warning("Nbits must be greater than zero.")
    try:
        rsa_encryption = RSAEncryption.new(nbits=nbits, **kwargs)
        # Display public key
        pubkey = json.dumps(rsa_encryption.pubkey.to_dict(), indent=4)
        st.markdown(
            markdown_content.format(
                key_type="Public Key",
                message="use this to encrypt messages.",
                json_content=pubkey,
                hex_alternative=pubkey.encode("utf-8").hex(),
            )
        )

        # Display private key
        privkey = json.dumps(rsa_encryption.privkey.to_dict(), indent=4)
        st.markdown(
            markdown_content.format(
                key_type="Private Key",
                message="use this to decrypt messages.",
                json_content=privkey,
                hex_alternative=privkey.encode("utf-8").hex(),
            )
        )
    except Exception as e:
        raise


def deserialize_key_payload(string: str, rec: int = 1) -> Optional[Dict]:
    if "{" in string:
        return json.loads(string)
    else:
        return deserialize_key_payload(
            string=bytes.fromhex(string).decode("utf-8"),
            rec=rec-1,
        ) if rec else None


def encrypt():
    markdown_content = textwrap.dedent("""
    ## Encrypted Message:
    
    ```text
    {encrypted_message}
    ```
    
    **A word of caution**: This message can only be decrypted with the associated private key.
    """)
    with st.form("encrypt-form"):
        message = st.text_area(label="Message")
        encryption_keys = deserialize_key_payload(
            st.text_input(label="Encryption keys (public)")
        )
        submitted = st.form_submit_button("Encrypt")
    if not submitted:
        return
    if not encryption_keys:
        return st.warning("Must provide a valid encryption key string (either json or hex)")
    try:
        key_wrapper = KeyWrapper.from_pubdict(dictionary=encryption_keys)
        st.markdown(
            markdown_content.format(
                encrypted_message=rsa_encrypt(
                    message=message,
                    pubkey=key_wrapper,
                    encoding="utf-8",
                )
            )
        )
    except Exception as e:
        raise


def decrypt():
    markdown_content = textwrap.dedent(
        """
        ## Decrypted Message
        
        ```text
        {decrypted_message}
        ```
        
        ----
        """
    )
    with st.form("decrypt-form"):
        encrypted_message = st.text_area(label="Encrypted Message")
        decryption_keys = deserialize_key_payload(
            st.text_input(label="Decryption keys (private)")
        )
        parse_request = st.checkbox(label="Parse as markdown", key="parse-request-element")
        submitted = st.form_submit_button("Decrypt")
    if not submitted:
        return
    if not decryption_keys:
        return st.warning("Must provide a valid decryption key string (either json or hex)")
    try:
        key_wrapper = KeyWrapper.from_privdict(dictionary=decryption_keys)
        message = rsa_decrypt(
            message=encrypted_message,
            privkey=key_wrapper,
            encoding="utf-8",
        )
        st.markdown(
            markdown_content.format(
                decrypted_message=message
            )
        )

        if parse_request:
            st.markdown(message, unsafe_allow_html=True)
    except Exception as e:
        st.warning(e)
        raise


def webui():
    option = sidebar().lower()
    if option == "encrypt":
        return encrypt()
    if option == "decrypt":
        return decrypt()
    if option == "create keys":
        return create_keys()


def main():
    logger.info("Staring the WebUI.")
    webui()


if __name__ == "__main__":
    main()

