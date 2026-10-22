//! Pont minimal vers l'API JavaScript de Tauri (`withGlobalTauri: true`) et le navigateur.

use rustchk_core::{AppError, Lang};
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke, catch)]
    async fn invoke_raw(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"], js_name = listen, catch)]
    async fn listen_raw(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["navigator", "clipboard"], js_name = writeText)]
    fn clipboard_write(text: &str) -> js_sys::Promise;
}

pub fn copy_to_clipboard(text: &str) {
    let _ = clipboard_write(text);
}

fn internal(detail: impl ToString) -> AppError {
    AppError::Internal { detail: detail.to_string() }
}

/// Le backend rejette avec une `AppError` sérialisée ; Tauri lui-même peut rejeter avec une simple chaîne.
fn js_error(e: JsValue) -> AppError {
    serde_wasm_bindgen::from_value::<AppError>(e.clone())
        .unwrap_or_else(|_| internal(e.as_string().unwrap_or_else(|| format!("{e:?}"))))
}

/// Appelle une commande Tauri avec des arguments sérialisables et décode la réponse.
pub async fn invoke<A: Serialize, R: DeserializeOwned>(cmd: &str, args: &A) -> Result<R, AppError> {
    let args = serde_wasm_bindgen::to_value(args).map_err(internal)?;
    let value = invoke_raw(cmd, args).await.map_err(js_error)?;
    serde_wasm_bindgen::from_value(value).map_err(internal)
}

/// Écoute un événement Tauri ; le gestionnaire reçoit la charge utile décodée.
/// L'écoute dure autant que l'application.
pub async fn listen<P: DeserializeOwned + 'static>(event: &str, mut handler: impl FnMut(P) + 'static) {
    let callback = Closure::<dyn FnMut(JsValue)>::new(move |raw: JsValue| {
        let payload = js_sys::Reflect::get(&raw, &JsValue::from_str("payload")).unwrap_or(JsValue::NULL);
        if let Ok(payload) = serde_wasm_bindgen::from_value::<P>(payload) {
            handler(payload);
        }
    });
    if listen_raw(event, &callback).await.is_ok() {
        callback.forget();
    }
}

#[derive(Serialize)]
pub struct NoArgs {}

#[derive(Serialize)]
pub struct LangArgs {
    pub lang: Lang,
}

// --- Langue : préférence mémorisée, repli sur la langue du navigateur ---

const LANG_STORAGE_KEY: &str = "rustchk.lang";

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

/// Langue au démarrage : choix précédent de l'utilisateur, sinon langue du système/navigateur
/// (français si c'est la sienne, anglais pour toute autre).
pub fn initial_lang() -> Lang {
    let saved =
        storage().and_then(|s| s.get_item(LANG_STORAGE_KEY).ok().flatten()).and_then(|tag| Lang::from_tag(&tag));
    saved.unwrap_or_else(|| {
        let browser = web_sys::window().and_then(|w| w.navigator().language()).unwrap_or_default();
        Lang::detect(&browser)
    })
}

/// Applique la langue au document (attribut `lang`, titre) et la mémorise.
pub fn apply_lang(lang: Lang, title: &str) {
    if let Some(s) = storage() {
        let _ = s.set_item(LANG_STORAGE_KEY, lang.tag());
    }
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        doc.set_title(title);
        if let Some(root) = doc.document_element() {
            let _ = root.set_attribute("lang", lang.tag());
        }
    }
}
