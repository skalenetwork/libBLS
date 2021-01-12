/*
Copyright (C) 2018-2019 SKALE Labs

This file is part of libBLS.

libBLS is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

libBLS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with libBLS.  If not, see <http://www.gnu.org/licenses/>.

@file dkgpython.cpp
@author Oleh Nikolaiev
@date 2019
*/

#include <stdio.h>

#include <Python.h>

#include <bls/BLSutils.h>
#include <bls/bls.h>
#include <dkg/dkg.h>

//////////////////////////
/// helper functions
//////////////////////////

static int IsPythonString( const PyObject* obj ) {
    // check for when an object is sent as an arg
#if PY_MAJOR_VERSION >= 3
    return PyUnicode_Check( obj ) || PyBytes_Check( obj );
#else
    return PyUnicode_Check( obj ) || PyString_Check( obj );
#endif
}

static PyObject* MakePythonString( const char* str ) {
    return Py_BuildValue( "s", str );
}

static PyObject* MakePythonString( const std::string& str ) {
    return MakePythonString( str.c_str() );
}

static PyObject* MakePythonInteger( long value ) {
    return Py_BuildValue( "l", value );
}

static PyObject* MakePythonBool( long value ) {
    return PyBool_FromLong( value );
}

static PyObject* MakePythonBool( bool value ) {
    return PyBool_FromLong( value ? 1 : 0 );
}


/////////////////////////
/// wrappers for DKG functions
/////////////////////////

struct PyDkgObject {
    PyObject_HEAD signatures::Dkg* pDKG;
};

static int PyDkgObject_init( struct PyDkgObject* self, PyObject* args, PyObject* kwds ) {
    unsigned long t = 0, n = 0;
    if ( !PyArg_ParseTuple( args, ( char* ) "kk", &t, &n ) ) {
        return -1;
    }

    self->pDKG = new signatures::Dkg( t, n );
    return 0;
}

static PyObject* PyDkgObject_repr( struct PyDkgObject* self ) {
    char repr[256];
    snprintf( repr, size_t( 0 ), "instance of DKG" );
    return MakePythonString( repr );
}

static void PyDkgObject_dealloc( struct PyDkgObject* self ) {
    if ( nullptr != self->pDKG ) {
        delete self->pDKG;
        self->pDKG = nullptr;
    }
#if PY_MAJOR_VERSION >= 3
    Py_TYPE( self )->tp_free( ( PyObject* ) self );  // introduced in python 2.6
#else
    self->ob_type->tp_free( ( PyObject* ) self );  // old way, removed in python 3
#endif
}

static PyObject* PyDkgObject_GeneratePolynomial(
    struct PyDkgObject* self, PyObject* args, PyObject* kwds ) {
    std::vector< libff::alt_bn128_Fr > ret_Val = self->pDKG->GeneratePolynomial();

    PyObject* pRetVal = PyList_New( self->pDKG->GetT() );
    for ( size_t i = 0; i < self->pDKG->GetT(); ++i ) {
        PyList_SetItem( pRetVal, i,
            MakePythonString( BLSutils::ConvertToString< libff::alt_bn128_Fr >( ret_Val[i] ) ) );
    }

    return pRetVal;
}

static PyObject* PyDkgObject_VerificationVector(
    struct PyDkgObject* self, PyObject* args, PyObject* kwds ) {
    PyObject* pyPolynomial;

    if ( !PyArg_ParseTuple( args, ( char* ) "O", &pyPolynomial ) ) {
        return -1;
    }

    if ( !PyList_Check( pyPolynomial ) ) {
        return -1;
    }

    std::vector< libff::alt_bn128_Fr > pol( self->pDKG->GetT() );

    for ( size_t i = 0; i < self->pDKG->GetT(); ++i ) {
        pol[i] = libff::alt_bn128_Fr(
            PyBytes_AsString( PyUnicode_AsUTF8String( PyList_GetItem( pyPolynomial, i ) ) ) );
    }

    std::vector< libff::alt_bn128_G2 > ret_Val = self->pDKG->VerificationVector( pol );

    PyObject* pRetVal = PyList_New( self->pDKG->GetT() );

    for ( size_t i = 0; i < self->pDKG->GetT(); ++i ) {
        ret_Val[i].to_affine_coordinates();

        PyObject* pFirstCoord = PyTuple_New( 2 );
        PyObject* pSecondCoord = PyTuple_New( 2 );

        PyTuple_SET_ITEM( pFirstCoord, 0,
            MakePythonString(
                BLSutils::ConvertToString< libff::alt_bn128_Fq >( ret_Val[i].X.c0 ).c_str() ) );
        PyTuple_SET_ITEM( pFirstCoord, 1,
            MakePythonString(
                BLSutils::ConvertToString< libff::alt_bn128_Fq >( ret_Val[i].X.c1 ).c_str() ) );
        PyTuple_SET_ITEM( pSecondCoord, 0,
            MakePythonString(
                BLSutils::ConvertToString< libff::alt_bn128_Fq >( ret_Val[i].Y.c0 ).c_str() ) );
        PyTuple_SET_ITEM( pSecondCoord, 1,
            MakePythonString(
                BLSutils::ConvertToString< libff::alt_bn128_Fq >( ret_Val[i].Y.c1 ).c_str() ) );

        PyObject* pyPublicKey = PyList_New( 2 );
        PyList_SetItem( pyPublicKey, 0, pFirstCoord );
        PyList_SetItem( pyPublicKey, 1, pSecondCoord );

        PyList_SetItem( pRetVal, i, pyPublicKey );
    }

    return pRetVal;
}

static PyObject* PyDkgObject_PolynomialValue(
    struct PyDkgObject* self, PyObject* args, PyObject* kwds ) {
    PyObject* pyPolynomial;
    size_t point;

    if ( !PyArg_ParseTuple( args, ( char* ) "Ok", &pyPolynomial, &point ) ) {
        return -1;
    }

    if ( !PyList_Check( pyPolynomial ) ) {
        return -1;
    }

    std::vector< libff::alt_bn128_Fr > pol( self->pDKG->GetT() );

    for ( size_t i = 0; i < self->pDKG->GetT(); ++i ) {
        pol[i] = libff::alt_bn128_Fr(
            PyBytes_AsString( PyUnicode_AsUTF8String( PyList_GetItem( pyPolynomial, i ) ) ) );
    }

    libff::alt_bn128_Fr ret_Val = self->pDKG->PolynomialValue( pol, point );

    PyObject* pRetVal =
        MakePythonString( BLSutils::ConvertToString< libff::alt_bn128_Fr >( ret_Val ) );

    return pRetVal;
}

static PyObject* PyDkgObject_SecretKeyContribution(
    struct PyDkgObject* self, PyObject* args, PyObject* kwds ) {
    PyObject* pyPolynomial;

    if ( !PyArg_ParseTuple( args, ( char* ) "O", &pyPolynomial ) ) {
        return -1;
    }

    if ( !PyList_Check( pyPolynomial ) ) {
        return -1;
    }

    std::vector< libff::alt_bn128_Fr > pol( self->pDKG->GetT() );

    for ( size_t i = 0; i < self->pDKG->GetT(); ++i ) {
        pol[i] = libff::alt_bn128_Fr(
            PyBytes_AsString( PyUnicode_AsUTF8String( PyList_GetItem( pyPolynomial, i ) ) ) );
    }

    std::vector< libff::alt_bn128_Fr > ret_Val = self->pDKG->SecretKeyContribution( pol );

    PyObject* pRetVal = PyList_New( self->pDKG->GetN() );

    for ( size_t i = 0; i < self->pDKG->GetN(); ++i ) {
        PyList_SetItem( pRetVal, i,
            MakePythonString( BLSutils::ConvertToString< libff::alt_bn128_Fr >( ret_Val[i] ) ) );
    }

    return pRetVal;
}

static PyObject* PyDkgObject_SecretKeyShareCreate(
    struct PyDkgObject* self, PyObject* args, PyObject* kwds ) {
    PyObject* pySecretKeyContribution;

    if ( !PyArg_ParseTuple( args, ( char* ) "O", &pySecretKeyContribution ) ) {
        return -1;
    }

    if ( !PyList_Check( pySecretKeyContribution ) ) {
        return -1;
    }

    std::vector< libff::alt_bn128_Fr > secretKeyContribution( self->pDKG->GetN() );

    for ( size_t i = 0; i < self->pDKG->GetN(); ++i ) {
        secretKeyContribution[i] = libff::alt_bn128_Fr( PyBytes_AsString(
            PyUnicode_AsUTF8String( PyList_GetItem( pySecretKeyContribution, i ) ) ) );
    }

    libff::alt_bn128_Fr ret_Val = self->pDKG->SecretKeyShareCreate( secretKeyContribution );

    PyObject* pRetVal =
        MakePythonString( BLSutils::ConvertToString< libff::alt_bn128_Fr >( ret_Val ) );

    return pRetVal;
}

static PyObject* PyDkgObject_Verification(
    struct PyDkgObject* self, PyObject* args, PyObject* kwds ) {
    size_t idx;
    char* pyShare = nullptr;
    PyObject* pyVerificationVector;

    if ( !PyArg_ParseTuple( args, ( char* ) "ksO", &idx, &pyShare, &pyVerificationVector ) ) {
        return -1;
    }

    if ( !PyList_Check( pyVerificationVector ) ) {
        return -1;
    }

    std::vector< libff::alt_bn128_G2 > verification_vector( self->pDKG->GetT() );

    for ( size_t i = 0; i < self->pDKG->GetT(); ++i ) {
        PyObject* value = PyList_GetItem( pyVerificationVector, i );
        if ( !PyList_Check( value ) ) {
            return -1;
        }

        libff::alt_bn128_G2 item;

        item.X = libff::alt_bn128_Fq2(
            libff::alt_bn128_Fq( PyBytes_AsString(
                PyUnicode_AsUTF8String( PyTuple_GetItem( PyList_GetItem( value, 0 ), 0 ) ) ) ),
            libff::alt_bn128_Fq( PyBytes_AsString(
                PyUnicode_AsUTF8String( PyTuple_GetItem( PyList_GetItem( value, 0 ), 1 ) ) ) ) );
        item.Y = libff::alt_bn128_Fq2(
            libff::alt_bn128_Fq( PyBytes_AsString(
                PyUnicode_AsUTF8String( PyTuple_GetItem( PyList_GetItem( value, 1 ), 0 ) ) ) ),
            libff::alt_bn128_Fq( PyBytes_AsString(
                PyUnicode_AsUTF8String( PyTuple_GetItem( PyList_GetItem( value, 1 ), 1 ) ) ) ) );
        item.Z = libff::alt_bn128_Fq2::one();

        verification_vector[i] = item;
    }

    bool res = self->pDKG->Verification( idx, libff::alt_bn128_Fr( pyShare ), verification_vector );

    PyObject* pRetVal = MakePythonBool( res );

    return pRetVal;
}

static PyObject* PyDkgObject_GetPublicKeyFromSecretKey(
    struct PyDkgObject* self, PyObject* args, PyObject* kwds ) {
    char* pyShare = nullptr;

    if ( !PyArg_ParseTuple( args, ( char* ) "s", &pyShare ) ) {
        return -1;
    }

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr( pyShare );

    libff::alt_bn128_G2 public_key = self->pDKG->GetPublicKeyFromSecretKey( secret_key );

    PyObject* pFirstCoord = PyTuple_New( 2 );
    PyObject* pSecondCoord = PyTuple_New( 2 );

    PyTuple_SET_ITEM( pFirstCoord, 0,
        MakePythonString(
            BLSutils::ConvertToString< libff::alt_bn128_Fq >( public_key.X.c0 ).c_str() ) );
    PyTuple_SET_ITEM( pFirstCoord, 1,
        MakePythonString(
            BLSutils::ConvertToString< libff::alt_bn128_Fq >( public_key.X.c1 ).c_str() ) );
    PyTuple_SET_ITEM( pSecondCoord, 0,
        MakePythonString(
            BLSutils::ConvertToString< libff::alt_bn128_Fq >( public_key.Y.c0 ).c_str() ) );
    PyTuple_SET_ITEM( pSecondCoord, 1,
        MakePythonString(
            BLSutils::ConvertToString< libff::alt_bn128_Fq >( public_key.Y.c1 ).c_str() ) );


    PyObject* pyPublicKey = PyList_New( 2 );
    PyList_SetItem( pyPublicKey, 0, pFirstCoord );
    PyList_SetItem( pyPublicKey, 1, pSecondCoord );

    return pyPublicKey;
}

static PyMethodDef PyDkgObject_methods[] = {
    {"GeneratePolynomial", ( PyCFunction ) PyDkgObject_GeneratePolynomial, METH_NOARGS,
        "generate random polynomial"},
    {"VerificationVector", ( PyCFunction ) PyDkgObject_VerificationVector, METH_VARARGS,
        "generate public values"},
    {"PolynomialValue", ( PyCFunction ) PyDkgObject_PolynomialValue, METH_VARARGS,
        "calculate value at point"},
    {"SecretKeyContribution", ( PyCFunction ) PyDkgObject_SecretKeyContribution, METH_VARARGS,
        "generate shares for others"},
    {"SecretKeyShareCreate", ( PyCFunction ) PyDkgObject_SecretKeyShareCreate, METH_VARARGS,
        "get a secret key from pieces"},
    {"Verification", ( PyCFunction ) PyDkgObject_Verification, METH_VARARGS,
        "verify recieved data"},
    {"GetPublicKeyFromSecretKey", ( PyCFunction ) PyDkgObject_GetPublicKeyFromSecretKey,
        METH_VARARGS, "get public key from secret key"},
    {"GetPublicKeyFromSecretKey", ( PyCFunction ) PyDkgObject_GetPublicKeyFromSecretKey,
        METH_VARARGS, "compute verification value"},
    {nullptr}};

static PyTypeObject PyDkgType = {
#if PY_MAJOR_VERSION >= 3
    PyVarObject_HEAD_INIT( nullptr, 0 )
#else
    PyObject_HEAD_INIT( nullptr ) 0,               // ob_size
#endif
        "dkgpython.dkg",                 // tp_name
    sizeof( struct PyDkgObject ),        // tp_basicsize
    0,                                   // tp_itemsize
    ( destructor ) PyDkgObject_dealloc,  // tp_dealloc
    0,                                   // tp_print
    0,                                   // tp_getattr
    0,                                   // tp_setattr
    0,                                   // tp_compare
    // 0,                      // tp_repr
    ( reprfunc ) PyDkgObject_repr,             // tp_repr
    0,                                         // tp_as_number
    0,                                         // tp_as_sequence
    0,                                         // tp_as_mapping
    0,                                         // tp_hash
    0,                                         // tp_call
    0,                                         // tp_str
    0,                                         // tp_getattro
    0,                                         // tp_setattro
    0,                                         // tp_as_buffer
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,  // tp_flags
    "DkgPython Class",                         // tp_doc
    0,                                         // tp_traverse
    0,                                         // tp_clear
    0,                                         // tp_richcompare
    0,                                         // tp_weaklistoffset
    0,                                         // tp_iter
    0,                                         // tp_iternext
    PyDkgObject_methods,                       // tp_methods
    0,                                         // tp_members
    0,                                         // tp_getset
    0,                                         // tp_base
    0,                                         // tp_dict
    0,                                         // tp_descr_get
    0,                                         // tp_descr_set
    0,                                         // tp_dictoffset
    // 0,                      // tp_init
    ( initproc ) PyDkgObject_init,  // tp_init
    0,                              // tp_alloc
    PyType_GenericNew,              // tp_new
};

static PyObject* say_hi_dkgpython_world( PyObject* self, PyObject* args ) {
    printf( "dkgpython, world!\n" );
    Py_RETURN_NONE;
}

static PyObject* say_hi_dkgpython_world2( PyObject* self, PyObject* args ) {
    const char* name;
    if ( !PyArg_ParseTuple( args, "s", &name ) ) {
        return nullptr;
    }

    printf( "say_hi_dkgpython_world2, %s!\n", name );
    Py_RETURN_NONE;
}

static PyMethodDef dkgpython_methods[] = {
    {"say_hi_dkgpython_world", say_hi_dkgpython_world, METH_NOARGS,
        "Print 'Hi dkgpython world' from a method defined in a C extension."},
    {"say_hi_dkgpython_world2", say_hi_dkgpython_world2, METH_VARARGS,
        "Print 'say_hi_dkgpython_world2 xxx' from a method defined in a C extension."},
    {nullptr, nullptr, 0, nullptr}};

static struct PyModuleDef dkgpython_definition = {PyModuleDef_HEAD_INIT, "dkgpython",
    "A Python module that prints 'Hi dkgpython world' from C code.", -1, dkgpython_methods};

PyMODINIT_FUNC PyInit_dkgpython() {
    Py_Initialize();

    if ( PyType_Ready( &PyDkgType ) < 0 ) {
        return nullptr;
    }

    PyObject* pModule = PyModule_Create( &dkgpython_definition );

    if ( !pModule ) {
        return nullptr;
    }

    Py_INCREF( &PyDkgType );
    PyModule_AddObject( pModule, "dkg", ( PyObject* ) &PyDkgType );

    return pModule;
}
