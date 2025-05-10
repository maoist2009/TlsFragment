The Scripts in this directory are used by Github Actions to build your packages.
These scripts can also be used to build your local builds.

Here is how to use these scripts to build your local packages using these scripts.


- Build for linux
   
   - To build on your linux distro::

      /bin/bash tools/build/build_linux.sh

   - To build using docker::

      - Install Docker[https://docs.docker.com/engine/install/].
      
      Run the following commands form this applications root dir.

       docker build . -t local -f tools/build/build_linux_amd64.dockerfile
       docker run -i -v $PWD:/srv -w/srv local /bin/bash ./tools/build/build_debian_8_docker.sh
    
  
- Build for Windows
    - WIP
- Build for android
    - WIP
- Build for ios
    - WIP
- Build for rpi
    -WIP