Installation
------------

To install your own copy of NSD you have two options: use the version provided
by your package manager, or download the source and building it yourself.

Installing via the `package manager
<https://repology.org/project/nsd/versions>`_ is the easiest option, and on most
systems even trivial. The downside is the distributed version can be outdated
for some distributions or not have all the compile-time options included that
you want. Building and compiling NSD yourself ensures that you have the latest
version and all the compile-time options you desire.

Introduction
============

NSD consists of two programs: the zone compiler ``zonec`` and the name server
``nsd`` itself. The name server works with an intermediate database prepared by
the zone compiler from standard zone files.

For NSD operation this means that zones have to be compiled by ``zonec`` before
NSD can use them. All this can be controlled via ``rc.d`` (SIGTERM,  SIGHUP) or
:command:`nsd-control`, and uses a simple configuration file  ``nsd.conf``.

Installing with a package manager
=================================

Most package managers maintain a version of NSD, although this version can be
outdated if this package has not been updated recently. If you like to upgrade
to the latest version, we recommend :ref:`compiling NSD yourself<Building from
source/Compiling>`.


Debian/Ubuntu
*************

Installing NSD with the built-in package manager should be as easy as:

.. code-block:: bash

    sudo apt update
    sudo apt install nsd

This gives you a compiled and running version of NSD ready to :doc:`be
configured<configuration>`.


Building from source/Compiling
==============================

Ubuntu 20.04 LTS
*************

First of all, we need our copy of the NSD code. `On our website
<https://nlnetlabs.nl/projects/nsd/about/>`_ you can find the latest version and
the changelog. In this example we'll use version 4.3.7. Please note that this is not the latest version currently.

.. code-block:: bash

    wget https://nlnetlabs.nl/downloads/nsd/nsd-4.3.7.tar.gz
    tar xzf nsd-4.3.7.tar.gz


We'll need some tools, such as a compiler and the :command:`make` program.

.. code-block:: bash

    sudo apt update
    sudo apt install -y build-essential


The library components NSD needs are: ``libssl`` and ``libevent``, of which we need
the "dev" version.

.. code-block:: bash

    sudo apt install -y libssl-dev
    sudo apt install -y libevent-dev


We'll also need the tools to build the actual program. For this, NSD uses
:command:`make` and internally it uses ``flex`` and ``yacc``, which we need to
download as well.

.. code-block:: bash

    sudo apt install -y bison
    sudo apt install -y flex


With all the requirements met, we can now start the compilation process in the
NSD directory.  The first step here is configuring. With :option:`./configure
-h` you can look at the extensive list of configurables for NSD. A nice
feature is that :command:`configure` will tell you what it's missing during
configuration.

.. code-block:: bash

    ./configure

If :command:`configure` gives no errors, we can continue to actually try compiling
NSD using :command:`make`; compilation might take a while.

.. code-block:: bash

    make

After successfully compiling, we can install NSD to make it available for
the machine.

.. code-block:: bash

    sudo make install

We now have fully compiled and installed version of NSD, and can continue
to testing it.


Testing
=======

A simple test to determine if the installation was successful is to invoke the
:command:`nsd` command with the :option:`-V` option, which is the "version"
option. This shows the version and build options used and proves installation
was successful.

.. code-block:: bash

    nsd -v

If all the previous steps were successful we can continue to configuring our NSD
instance.

Another handy trick you can use during testing is to run NSD in the foreground
using the :option:`-d` option and increase the verbosity level using the
:option:`-V 3` option. This allows you to see steps NSD takes and also where it
fails.

Now that NSD is installed we can :doc:`continue to configuring
it<configuration>`.
