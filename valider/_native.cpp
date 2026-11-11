#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <cstdint>
#include <memory>
#include <new>
#include <string>
#include <unordered_set>
#include <utility>

extern "C" std::int32_t valider_http_status_class(std::uint16_t status);
extern "C" bool valider_http_status_retryable(std::uint16_t status);

namespace {

constexpr Py_ssize_t kMaximumRedirects = 10;

struct DomainPolicy {
    PyObject_HEAD
    std::unordered_set<std::string>* domains;
    std::unordered_set<std::string>* visited_urls;
    Py_ssize_t maximum_redirects;
    Py_ssize_t redirect_count;
};

bool read_unicode(PyObject* value, std::string& output) {
    if (!PyUnicode_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "domain and URL values must be strings");
        return false;
    }

    Py_ssize_t length = 0;
    const char* data = PyUnicode_AsUTF8AndSize(value, &length);
    if (data == nullptr) {
        return false;
    }
    try {
        output.assign(data, static_cast<std::size_t>(length));
    } catch (const std::bad_alloc&) {
        PyErr_NoMemory();
        return false;
    }
    return true;
}

bool is_canonical_domain(const std::string& domain) {
    if (domain.empty() || domain.size() > 253) {
        return false;
    }

    std::size_t label_start = 0;
    while (label_start < domain.size()) {
        const std::size_t dot = domain.find('.', label_start);
        const std::size_t label_end = dot == std::string::npos ? domain.size() : dot;
        const std::size_t label_length = label_end - label_start;
        if (label_length == 0 || label_length > 63 ||
            domain[label_start] == '-' || domain[label_end - 1] == '-') {
            return false;
        }

        for (std::size_t index = label_start; index < label_end; ++index) {
            const char character = domain[index];
            if (!((character >= 'a' && character <= 'z') ||
                  (character >= '0' && character <= '9') || character == '-')) {
                return false;
            }
        }

        if (dot == std::string::npos) {
            break;
        }
        label_start = dot + 1;
    }
    return true;
}

bool is_initialized(const DomainPolicy* self) {
    if (self->domains != nullptr && self->visited_urls != nullptr) {
        return true;
    }
    PyErr_SetString(PyExc_RuntimeError, "DomainPolicy is not initialized");
    return false;
}

PyObject* policy_new(PyTypeObject* type, PyObject*, PyObject*) {
    auto* self = reinterpret_cast<DomainPolicy*>(type->tp_alloc(type, 0));
    if (self != nullptr) {
        self->domains = nullptr;
        self->visited_urls = nullptr;
        self->maximum_redirects = 0;
        self->redirect_count = 0;
    }
    return reinterpret_cast<PyObject*>(self);
}

int policy_init(DomainPolicy* self, PyObject* args, PyObject* kwargs) {
    PyObject* domains_object = nullptr;
    Py_ssize_t maximum_redirects = kMaximumRedirects;
    static const char* keywords[] = {"domains", "max_redirects", nullptr};
    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "O|n", const_cast<char**>(keywords),
            &domains_object, &maximum_redirects)) {
        return -1;
    }
    if (maximum_redirects < 0 || maximum_redirects > kMaximumRedirects) {
        PyErr_Format(
            PyExc_ValueError, "max_redirects must be between 0 and %zd",
            kMaximumRedirects);
        return -1;
    }

    PyObject* sequence = PySequence_Fast(domains_object, "domains must be a sequence");
    if (sequence == nullptr) {
        return -1;
    }

    try {
        std::unordered_set<std::string> validated_domains;
        const Py_ssize_t count = PySequence_Fast_GET_SIZE(sequence);
        if (count == 0) {
            Py_DECREF(sequence);
            PyErr_SetString(PyExc_ValueError, "at least one authorized domain is required");
            return -1;
        }
        validated_domains.reserve(static_cast<std::size_t>(count));

        for (Py_ssize_t index = 0; index < count; ++index) {
            std::string domain;
            if (!read_unicode(PySequence_Fast_GET_ITEM(sequence, index), domain)) {
                Py_DECREF(sequence);
                return -1;
            }
            if (!is_canonical_domain(domain)) {
                Py_DECREF(sequence);
                PyErr_SetString(
                    PyExc_ValueError,
                    "domains must be canonical lowercase ASCII domain names");
                return -1;
            }
            validated_domains.insert(std::move(domain));
        }
        Py_DECREF(sequence);

        auto new_domains =
            std::make_unique<std::unordered_set<std::string>>(std::move(validated_domains));
        auto new_visited_urls = std::make_unique<std::unordered_set<std::string>>();
        delete self->domains;
        delete self->visited_urls;
        self->domains = new_domains.release();
        self->visited_urls = new_visited_urls.release();
        self->maximum_redirects = maximum_redirects;
        self->redirect_count = 0;
        return 0;
    } catch (const std::bad_alloc&) {
        PyErr_NoMemory();
        return -1;
    }
}

void policy_dealloc(DomainPolicy* self) {
    delete self->domains;
    delete self->visited_urls;
    Py_TYPE(self)->tp_free(reinterpret_cast<PyObject*>(self));
}

PyObject* policy_begin(DomainPolicy* self, PyObject*) {
    if (!is_initialized(self)) {
        return nullptr;
    }
    self->visited_urls->clear();
    self->redirect_count = 0;
    Py_RETURN_NONE;
}

PyObject* policy_is_allowed(DomainPolicy* self, PyObject* value) {
    if (!is_initialized(self)) {
        return nullptr;
    }
    std::string host;
    if (!read_unicode(value, host)) {
        return nullptr;
    }
    if (!is_canonical_domain(host)) {
        Py_RETURN_FALSE;
    }

    std::size_t label_start = 0;
    while (label_start < host.size()) {
        if (self->domains->find(host.substr(label_start)) != self->domains->end()) {
            Py_RETURN_TRUE;
        }
        const std::size_t dot = host.find('.', label_start);
        if (dot == std::string::npos) {
            break;
        }
        label_start = dot + 1;
    }
    Py_RETURN_FALSE;
}

PyObject* policy_visit_url(DomainPolicy* self, PyObject* value) {
    if (!is_initialized(self)) {
        return nullptr;
    }
    std::string url;
    if (!read_unicode(value, url)) {
        return nullptr;
    }
    try {
        if (self->visited_urls->insert(std::move(url)).second) {
            Py_RETURN_TRUE;
        }
    } catch (const std::bad_alloc&) {
        return PyErr_NoMemory();
    }
    Py_RETURN_FALSE;
}

PyObject* policy_follow_redirect(DomainPolicy* self, PyObject*) {
    if (!is_initialized(self)) {
        return nullptr;
    }
    if (self->redirect_count >= self->maximum_redirects) {
        Py_RETURN_FALSE;
    }
    ++self->redirect_count;
    Py_RETURN_TRUE;
}

PyMethodDef policy_methods[] = {
    {"begin", reinterpret_cast<PyCFunction>(policy_begin), METH_NOARGS,
     "Reset redirect and visited-URL state for a new validation."},
    {"is_allowed", reinterpret_cast<PyCFunction>(policy_is_allowed), METH_O,
     "Return whether a canonical host matches an authorized domain."},
    {"visit_url", reinterpret_cast<PyCFunction>(policy_visit_url), METH_O,
     "Record a URL and reject repeats in the current redirect chain."},
    {"follow_redirect", reinterpret_cast<PyCFunction>(policy_follow_redirect), METH_NOARGS,
     "Consume one redirect allowance, returning false at the configured limit."},
    {nullptr, nullptr, 0, nullptr},
};

PyTypeObject policy_type = {PyVarObject_HEAD_INIT(nullptr, 0)};

PyObject* classify_http_status(PyObject*, PyObject* value) {
    const long status = PyLong_AsLong(value);
    if (status == -1 && PyErr_Occurred()) {
        return nullptr;
    }
    if (status < 0 || status > 65535) {
        PyErr_SetString(PyExc_ValueError, "HTTP status must be between 0 and 65535");
        return nullptr;
    }

    static const char* names[] = {
        "invalid", "informational", "success", "redirection", "client_error", "server_error"
    };
    const std::int32_t category =
        valider_http_status_class(static_cast<std::uint16_t>(status));
    if (category < 0 || category >= static_cast<std::int32_t>(sizeof(names) / sizeof(names[0]))) {
        PyErr_SetString(PyExc_RuntimeError, "Rust returned an invalid HTTP status class");
        return nullptr;
    }
    return PyUnicode_FromString(names[category]);
}

PyObject* is_retryable_http_status(PyObject*, PyObject* value) {
    const long status = PyLong_AsLong(value);
    if (status == -1 && PyErr_Occurred()) {
        return nullptr;
    }
    if (status < 0 || status > 65535) {
        PyErr_SetString(PyExc_ValueError, "HTTP status must be between 0 and 65535");
        return nullptr;
    }
    return PyBool_FromLong(
        valider_http_status_retryable(static_cast<std::uint16_t>(status)));
}

PyMethodDef module_methods[] = {
    {"classify_http_status", classify_http_status, METH_O,
     "Classify an HTTP response code using the Rust analysis core."},
    {"is_retryable_http_status", is_retryable_http_status, METH_O,
     "Return a technical retryability hint without performing retries."},
    {nullptr, nullptr, 0, nullptr},
};

PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    "_native",
    "C++ authorization policy and Rust HTTP status classification.",
    -1,
    module_methods,
};

}  // namespace

PyMODINIT_FUNC PyInit__native() {
    policy_type.tp_name = "valider._native.DomainPolicy";
    policy_type.tp_basicsize = sizeof(DomainPolicy);
    policy_type.tp_itemsize = 0;
    policy_type.tp_flags = Py_TPFLAGS_DEFAULT;
    policy_type.tp_new = policy_new;
    policy_type.tp_init = reinterpret_cast<initproc>(policy_init);
    policy_type.tp_dealloc = reinterpret_cast<destructor>(policy_dealloc);
    policy_type.tp_methods = policy_methods;
    policy_type.tp_doc = "Typed, per-run authorization and redirect-chain policy.";

    if (PyType_Ready(&policy_type) < 0) {
        return nullptr;
    }

    PyObject* module = PyModule_Create(&module_definition);
    if (module == nullptr) {
        return nullptr;
    }
    Py_INCREF(&policy_type);
    if (PyModule_AddObject(
            module, "DomainPolicy", reinterpret_cast<PyObject*>(&policy_type)) < 0) {
        Py_DECREF(&policy_type);
        Py_DECREF(module);
        return nullptr;
    }
    return module;
}
